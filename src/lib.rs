use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

const REDIRECT_URI: &str = "urn:ietf:wg:oauth:2.0:oob";
const SCOPES: &str = "read write follow";

pub struct MastodonClient {
    base_url: String,
    user_agent: String,
    client_name: String,
    website: String,

    access_token: String,
}

pub type GetAuthorizationCodeCallback = Box<dyn FnMut(&str) -> Result<String, MastodonClientError>>;

impl MastodonClient {
    pub fn new(
        base_url: impl Into<String>,
        user_agent: impl Into<String>,
        client_name: impl Into<String>,
        website: impl Into<String>,
    ) -> Self {
        let base_url = base_url.into();
        let user_agent = user_agent.into();
        let client_name = client_name.into();
        let website = website.into();

        Self {
            base_url,
            user_agent,
            client_name,
            website,
            access_token: "".to_string(),
        }
    }

    pub fn authorize(
        &mut self,
        cached_access_token: Option<impl Into<String>>,
        get_authorization_code_callback: GetAuthorizationCodeCallback,
    ) -> Result<(), MastodonClientError> {
        if self.access_token.is_empty() {
            self.access_token = cached_access_token.map(|x| x.into()).unwrap_or(Self::login(
                self.base_url.as_str(),
                self.user_agent.as_str(),
                self.client_name.as_str(),
                self.website.as_str(),
                get_authorization_code_callback,
            )?);
        }
        Ok(())
    }

    pub fn home_timeline(&self) -> Result<HomeTimeline, MastodonClientError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(&self.user_agent)
            .build()?;

        let response = client
            .get(format!(r"{}/api/v1/timelines/home", self.base_url))
            .bearer_auth(&self.access_token)
            .send()?
            .text()?;

        Ok(serde_json::from_str(&response)?)
    }

    pub fn verify_credentials(&self) -> Result<Account, MastodonClientError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(&self.user_agent)
            .build()?;

        let response = client
            .get(format!(
                r"{}/api/v1/accounts/verify_credentials",
                self.base_url
            ))
            .bearer_auth(&self.access_token)
            .send()?
            .text()?;

        Ok(serde_json::from_str(&response)?)
    }

    fn login(
        base_url: &str,
        user_agent: &str,
        client_name: &str,
        website: &str,
        mut get_authorization_code_callback: GetAuthorizationCodeCallback,
    ) -> Result<String, MastodonClientError> {
        #[derive(Debug, Serialize, Deserialize)]
        struct CreateAppResponse {
            id: String,
            name: String,
            website: String,
            redirect_uri: String,
            client_id: String,
            client_secret: String,
        }

        let create_app = || -> Result<CreateAppResponse, MastodonClientError> {
            let url = format!(r"{}/api/v1/apps", base_url);

            let client = reqwest::blocking::Client::builder()
                .user_agent(user_agent)
                .build()?;
            let response = client
                .post(url)
                .form(&HashMap::from([
                    ("client_name", client_name),
                    ("redirect_uris", REDIRECT_URI),
                    ("scopes", SCOPES),
                    ("website", website),
                ]))
                .send();
            Ok(serde_json::from_str(&response?.text()?)?)
        };

        let get_login_url = |client_id: &str| -> String {
            format!(
                r"{}/oauth/authorize?{}",
                base_url,
                url::form_urlencoded::Serializer::new(String::new())
                    .append_pair("response_type", "code")
                    .append_pair("redirect_uri", REDIRECT_URI)
                    .append_pair("scope", SCOPES)
                    .append_pair("client_id", client_id)
                    .finish()
            )
        };

        #[derive(Debug, Serialize, Deserialize)]
        struct RequestAccessTokenResponse {
            access_token: String,
            created_at: u32,
            scope: String,
            token_type: String,
        }

        let request_access_token =
            |client_id: &str,
             client_secret: &str,
             authorization_code: &str|
             -> Result<RequestAccessTokenResponse, MastodonClientError> {
                let url = format!(r"{}/oauth/token", base_url);

                let client = reqwest::blocking::Client::builder()
                    .user_agent(user_agent)
                    .build()?;
                let response = client
                    .post(url)
                    .form(&HashMap::from([
                        ("grant_type", "authorization_code"),
                        ("client_id", client_id),
                        ("client_secret", client_secret),
                        ("code", authorization_code),
                        ("redirect_uri", REDIRECT_URI),
                    ]))
                    .send();
                Ok(serde_json::from_str(&response?.text()?)?)
            };

        let response = create_app()?;

        let client_id = response.client_id;
        let client_secret = response.client_secret;

        let login_url = get_login_url(&client_id);
        let authorization_code = get_authorization_code_callback(login_url.as_str())?;
        let authorization_code = authorization_code.trim();

        let response = request_access_token(&client_id, &client_secret, authorization_code)?;
        Ok(response.access_token)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HomeTimeline {
    pub statuses: Vec<Status>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    /// ID of the status in the database.
    pub id: String,
    /// URI of the status used for federation.
    pub uri: String,
    /// The date when this status was created.
    pub created_at: String,
    /// The account that authored this status.
    pub account: Account,
    /// HTML-encoded status content.
    pub content: String,
    /// Visibility of this status.
    pub visibility: String,
    /// Is this status marked as sensitive content?
    pub sensitive: bool,
    /// Subject or summary line, below which status content is collapsed until expanded.
    pub spoiler_text: String,
    /// Media that is attached to this status.
    pub media_attachments: Vec<MediaAttachment>,
    /// The application used to post this status.
    pub application: Option<Application>,
    /// Mentions of users within the status content.
    pub mentions: Vec<StatusMention>,
    /// Hashtags used within the status content
    pub tags: Vec<StatusTag>,
    /// Custom emoji to be used when rendering status content.
    pub emojis: Vec<CustomEmoji>,
    /// How many boosts this status has received.
    pub reblogs_count: u32,
    /// How many favourites this status has received.
    pub favourites_count: u32,
    /// How many replies this status has received.
    pub replies_count: u32,
    /// A link to the status’s HTML representation.
    pub url: Option<String>,
    /// ID of the status being replied to.
    pub in_reply_to_id: Option<String>,
    /// ID of the account that authored the status being replied to.
    pub in_reply_to_account_id: Option<String>,
    /// The status being reblogged.
    pub reblog: Option<Box<Status>>,
    /// The poll attached to the status.
    pub poll: Option<Poll>,
    /// Preview card for links included within status content.
    pub card: Option<PreviewCard>,
    /// Primary language of this status.
    pub language: Option<String>,
    /// Plain-text source of a status. Returned instead of content when status is deleted, so the user may redraft from
    /// the source text without the client having to reverse-engineer the original text from the HTML content.
    pub text: Option<String>,
    /// Timestamp of when the status was last edited.
    pub edited_at: Option<String>,
    /// If the current token has an authorized user: Have you favourited this status?
    pub favourited: Option<bool>,
    /// If the current token has an authorized user: Have you boosted this status?
    pub reblogged: Option<bool>,
    /// If the current token has an authorized user: Have you muted notifications for this status’s conversation?
    pub muted: Option<bool>,
    /// If the current token has an authorized user: Have you bookmarked this status?
    pub bookmarked: Option<bool>,
    /// If the current token has an authorized user: Have you pinned this status? Only appears if the status is pinnable.
    pub pinned: Option<bool>,
    /// If the current token has an authorized user: The filter and keywords that matched this status.
    pub filtered: Option<FilterResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterResult {
    /// The filter that was matched
    pub filter: Filter,
    /// The keyword within the filter that was matched.
    pub keyword_matches: Option<Vec<String>>,
    /// The status ID within the filter that was matched.
    pub status_matches: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Filter {
    /// The ID of the Filter in the database.
    pub id: String,
    /// A title given by the user to name the filter.
    pub title: String,
    /// The contexts in which the filter should be applied.
    pub context: Vec<String>,
    /// When the filter should no longer be applied.
    pub expires_at: Option<String>,
    /// The action to be taken when a status matches this filter.
    pub filter_action: String,
    /// The keywords grouped under this filter.
    pub keywords: Vec<FilterKeyword>,
    /// The statuses grouped under this filter.
    pub statuses: Vec<FilterStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterStatus {
    /// The ID of the FilterStatus in the database.
    pub id: String,
    /// The ID of the Status that will be filtered.
    pub status_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterKeyword {
    /// The ID of the FilterKeyword in the database.
    pub id: String,
    /// The phrase to be matched against.
    pub keyword: String,
    /// Should the filter consider word boundaries?
    pub whole_word: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Poll {
    /// The ID of the poll in the database.
    pub id: String,
    /// When the poll ends.
    pub expires_at: Option<String>,
    /// Is the poll currently expired?
    pub expired: bool,
    /// Does the poll allow multiple-choice answers?
    pub multiple: bool,
    /// How many votes have been received.
    pub votes_count: u32,
    /// How many unique accounts have voted on a multiple-choice poll.
    pub voters_count: Option<u32>,
    /// Possible answers for the pool.
    pub options: Vec<PollOption>,
    /// Custom emoji to be used for rendering poll options.
    pub emojis: Vec<CustomEmoji>,
    /// When called with a user token, has the authorized user voted?
    pub voted: Option<bool>,
    /// Possible answers for the pool.
    pub own_votes: Option<Vec<u32>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PollOption {
    /// The text value of the poll option.
    pub title: String,
    /// The total number of received votes for this option.
    pub votes_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CustomEmoji {
    /// The name of the custom emoji.
    pub shortcode: String,
    /// A link to the custom emoji.
    pub url: String,
    /// A link to a static copy of the custom emoji.
    pub static_url: String,
    /// Whether this Emoji should be visible in the picker or unlisted.
    pub visible_in_picker: bool,
    /// Used for sorting custom emoji in the picker.
    pub category: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PreviewCard {
    /// Location of linked resource.
    pub url: String,
    /// Title of linked resource.
    pub title: String,
    /// Description of preview.
    pub description: String,
    /// The type of the attachment.
    #[serde(rename = "type")]
    pub kind: String,
    /// The author of the original resource.
    pub author_name: String,
    /// A link to the author of the original resource.
    pub author_url: String,
    /// The provider of the original resource.
    pub provider_name: String,
    /// A link to the provider of the original resource.
    pub provider_url: String,
    /// HTML to be used for generating the preview card.
    pub html: String,
    /// Width of preview, in pixels.
    pub width: u32,
    /// Height of preview, in pixels.
    pub height: u32,
    /// Preview thumbnail.
    pub image: Option<String>,
    /// Used for photo embeds, instead of custom html.
    pub embed_url: String,
    /// A hash computed by the BlurHash algorithm, for generating colorful preview thumbnails when media has not been
    /// downloaded yet.
    pub blurhash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MediaAttachment {
    /// The ID of the attachment in the database.
    pub id: String,
    /// The type of the attachment.
    #[serde(rename = "type")]
    pub kind: String,
    /// The location of the original full-size attachment.
    pub url: String,
    /// The location of a scaled-down preview of the attachment.
    pub preview_url: String,
    /// The location of the full-size original attachment on the remote website.
    pub remote_url: Option<String>,
    /// Metadata returned by Paperclip.
    pub meta: HashMap<String, serde_json::Value>,
    /// Alternate text that describes what is in the media attachment, to be used for the visually impaired or when
    /// media attachments do not load.
    pub description: Option<String>,
    /// A hash computed by the BlurHash algorithm, for generating colorful preview thumbnails when media has not been
    /// downloaded yet.
    pub blurhash: String,
    /// A shorter URL for the attachment.
    #[deprecated]
    pub text_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusTag {
    /// The value of the hashtag after the # sign.
    pub name: String,
    /// A link to the hashtag on the instance.
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusMention {
    /// The account ID of the mentioned user.
    pub id: String,
    /// The username of the mentioned user.
    pub username: String,
    /// The location of the mentioned user’s profile.
    pub url: String,
    /// The webfinger acct: URI of the mentioned user. Equivalent to username for local users, or username@domain for
    /// remote users.
    pub acct: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Application {
    pub name: String,
    pub website: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub username: String,
    pub acct: String,
    pub display_name: String,
    pub locked: bool,
    pub discoverable: bool,
    pub bot: bool,
    pub created_at: String,
    pub note: String,
    pub url: String,
    pub avatar: String,
    pub avatar_static: String,
    pub header: String,
    pub header_static: String,
    pub followers_count: u32,
    pub following_count: u32,
    pub statuses_count: u32,
    pub last_status_at: String,
    pub source: Option<CredentialsSource>,
    pub role: Option<Role>,
    pub emojis: Vec<AccountEmoji>,
    pub fields: Vec<AccountField>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Role {
    /// The ID of the Role in the database.
    pub id: Option<u32>,
    /// The name of the role.
    pub name: String,
    /// The hex code assigned to this role. If no hex code is assigned, the string will be empty.
    pub color: Option<String>,
    /// A bitmask that represents the sum of all permissions granted to the role.
    pub permissions: Option<u32>,
    /// Whether the role is publicly visible as a badge on user profiles.
    #[serde(default)]
    pub highlighted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialsSource {
    pub privacy: String,
    pub sensitive: bool,
    pub language: String,
    pub note: String,
    pub fields: Vec<AccountField>,
    pub follow_requests_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountField {
    pub name: String,
    pub value: String,
    pub verified_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountEmoji {
    pub shortcode: String,
    pub url: String,
    pub static_url: String,
    pub visible_in_picker: bool,
}

#[derive(Error, Debug)]
pub enum MastodonClientError {
    #[error("failed request")]
    Request(#[from] reqwest::Error),
    #[error("failed JSON parsing")]
    JSON(#[from] std::io::Error),
    #[error("failed IO")]
    IO(#[from] serde_json::Error),
    #[error("failed getting authorization code: {0}")]
    AuthorizationCode(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use dialog::DialogBox;

    #[test]
    fn mastodon_test() {
        let base_url = r"https://fedi.sszczyrb.dev";
        let user_agent = "nodotsam";
        let client_name = "nodotsam";
        let website = r"https://github.com/szx/nodotsam";

        let mut mastodon_client = MastodonClient::new(base_url, user_agent, client_name, website);
        mastodon_client
            .authorize(
                None::<String>,
                Box::new(|login_url: &str| -> Result<String, MastodonClientError> {
                    webbrowser::open(login_url)
                        .map_err(|err| MastodonClientError::AuthorizationCode(err.to_string()))?;
                    dialog::Input::new("authorization code")
                        .title("authorization code")
                        .show()
                        .map_err(|err| MastodonClientError::AuthorizationCode(err.to_string()))?
                        .ok_or(MastodonClientError::AuthorizationCode(
                            "empty code".to_string(),
                        ))
                }),
            )
            .unwrap();

        mastodon_client.verify_credentials().unwrap();
        mastodon_client.home_timeline().unwrap();
    }
}
