use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

const REDIRECT_URI: &str = "urn:ietf:wg:oauth:2.0:oob";
const SCOPES: &str = "read write follow";

pub struct MastodonClient {
    base_url: String,
    user_agent: String,
    access_token: String,
}

pub type GetAuthorizationCodeCallback = Box<dyn FnMut(&str) -> Result<String, MastodonClientError>>;

impl MastodonClient {
    pub fn new(
        base_url: impl Into<String>,
        user_agent: impl Into<String>,
        client_name: impl AsRef<str>,
        website: impl AsRef<str>,
        cached_access_token: Option<impl Into<String>>,
        get_authorization_code_callback: GetAuthorizationCodeCallback,
    ) -> Result<Self, MastodonClientError> {
        let base_url = base_url.into();
        let user_agent = user_agent.into();
        let client_name = client_name.as_ref();
        let website = website.as_ref();
        let access_token = cached_access_token.map(|x| x.into()).unwrap_or(Self::login(
            base_url.as_str(),
            user_agent.as_str(),
            client_name,
            website,
            get_authorization_code_callback,
        )?);

        Ok(Self {
            base_url,
            user_agent,
            access_token,
        })
    }

    fn home_timeline(&self) -> Result<HomeTimeline, MastodonClientError> {
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

    fn verify_credentials(&self) -> Result<Account, MastodonClientError> {
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
struct HomeTimeline {
    emojis: Vec<Status>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Status {
    /// ID of the status in the database.
    id: String,
    /// URI of the status used for federation.
    uri: String,
    /// The date when this status was created.
    created_at: String,
    /// The account that authored this status.
    account: Account,
    /// HTML-encoded status content.
    content: String,
    /// Visibility of this status.
    visibility: String,
    /// Is this status marked as sensitive content?
    sensitive: bool,
    /// Subject or summary line, below which status content is collapsed until expanded.
    spoiler_text: String,
    /// Media that is attached to this status.
    media_attachments: Vec<MediaAttachment>,
    /// The application used to post this status.
    application: Option<Application>,
    /// Mentions of users within the status content.
    mentions: Vec<StatusMention>,
    /// Hashtags used within the status content
    tags: Vec<StatusTag>,
    /// Custom emoji to be used when rendering status content.
    emojis: Vec<CustomEmoji>,
    /// How many boosts this status has received.
    reblogs_count: u32,
    /// How many favourites this status has received.
    favourites_count: u32,
    /// How many replies this status has received.
    replies_count: u32,
    /// A link to the status’s HTML representation.
    url: Option<String>,
    /// ID of the status being replied to.
    in_reply_to_id: Option<String>,
    /// ID of the account that authored the status being replied to.
    in_reply_to_account_id: Option<String>,
    /// The status being reblogged.
    reblog: Option<Box<Status>>,
    /// The poll attached to the status.
    poll: Option<Poll>,
    /// Preview card for links included within status content.
    card: Option<PreviewCard>,
    /// Primary language of this status.
    language: Option<String>,
    /// Plain-text source of a status. Returned instead of content when status is deleted, so the user may redraft from
    /// the source text without the client having to reverse-engineer the original text from the HTML content.
    text: Option<String>,
    /// Timestamp of when the status was last edited.
    edited_at: Option<String>,
    /// If the current token has an authorized user: Have you favourited this status?
    favourited: Option<bool>,
    /// If the current token has an authorized user: Have you boosted this status?
    reblogged: Option<bool>,
    /// If the current token has an authorized user: Have you muted notifications for this status’s conversation?
    muted: Option<bool>,
    /// If the current token has an authorized user: Have you bookmarked this status?
    bookmarked: Option<bool>,
    /// If the current token has an authorized user: Have you pinned this status? Only appears if the status is pinnable.
    pinned: Option<bool>,
    /// If the current token has an authorized user: The filter and keywords that matched this status.
    filtered: Option<FilterResult>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FilterResult {
    /// The filter that was matched
    filter: Filter,
    /// The keyword within the filter that was matched.
    keyword_matches: Option<Vec<String>>,
    /// The status ID within the filter that was matched.
    status_matches: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Filter {
    /// The ID of the Filter in the database.
    id: String,
    /// A title given by the user to name the filter.
    title: String,
    /// The contexts in which the filter should be applied.
    context: Vec<String>,
    /// When the filter should no longer be applied.
    expires_at: Option<String>,
    /// The action to be taken when a status matches this filter.
    filter_action: String,
    /// The keywords grouped under this filter.
    keywords: Vec<FilterKeyword>,
    /// The statuses grouped under this filter.
    statuses: Vec<FilterStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FilterStatus {
    /// The ID of the FilterStatus in the database.
    id: String,
    /// The ID of the Status that will be filtered.
    status_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct FilterKeyword {
    /// The ID of the FilterKeyword in the database.
    id: String,
    /// The phrase to be matched against.
    keyword: String,
    /// Should the filter consider word boundaries?
    whole_word: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Poll {
    /// The ID of the poll in the database.
    id: String,
    /// When the poll ends.
    expires_at: Option<String>,
    /// Is the poll currently expired?
    expired: bool,
    /// Does the poll allow multiple-choice answers?
    multiple: bool,
    /// How many votes have been received.
    votes_count: u32,
    /// How many unique accounts have voted on a multiple-choice poll.
    voters_count: Option<u32>,
    /// Possible answers for the pool.
    options: Vec<PollOption>,
    /// Custom emoji to be used for rendering poll options.
    emojis: Vec<CustomEmoji>,
    /// When called with a user token, has the authorized user voted?
    voted: Option<bool>,
    /// Possible answers for the pool.
    own_votes: Option<Vec<u32>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PollOption {
    /// The text value of the poll option.
    title: String,
    /// The total number of received votes for this option.
    votes_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CustomEmoji {
    /// The name of the custom emoji.
    shortcode: String,
    /// A link to the custom emoji.
    url: String,
    /// A link to a static copy of the custom emoji.
    static_url: String,
    /// Whether this Emoji should be visible in the picker or unlisted.
    visible_in_picker: bool,
    /// Used for sorting custom emoji in the picker.
    category: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PreviewCard {
    /// Location of linked resource.
    url: String,
    /// Title of linked resource.
    title: String,
    /// Description of preview.
    description: String,
    /// The type of the attachment.
    #[serde(rename = "type")]
    kind: String,
    /// The author of the original resource.
    author_name: String,
    /// A link to the author of the original resource.
    author_url: String,
    /// The provider of the original resource.
    provider_name: String,
    /// A link to the provider of the original resource.
    provider_url: String,
    /// HTML to be used for generating the preview card.
    html: String,
    /// Width of preview, in pixels.
    width: u32,
    /// Height of preview, in pixels.
    height: u32,
    /// Preview thumbnail.
    image: Option<String>,
    /// Used for photo embeds, instead of custom html.
    embed_url: String,
    /// A hash computed by the BlurHash algorithm, for generating colorful preview thumbnails when media has not been
    /// downloaded yet.
    blurhash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MediaAttachment {
    /// The ID of the attachment in the database.
    id: String,
    /// The type of the attachment.
    #[serde(rename = "type")]
    kind: String,
    /// The location of the original full-size attachment.
    url: String,
    /// The location of a scaled-down preview of the attachment.
    preview_url: String,
    /// The location of the full-size original attachment on the remote website.
    remote_url: Option<String>,
    /// Metadata returned by Paperclip.
    meta: HashMap<String, serde_json::Value>,
    /// Alternate text that describes what is in the media attachment, to be used for the visually impaired or when
    /// media attachments do not load.
    description: Option<String>,
    /// A hash computed by the BlurHash algorithm, for generating colorful preview thumbnails when media has not been
    /// downloaded yet.
    blurhash: String,
    /// A shorter URL for the attachment.
    #[deprecated]
    text_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StatusTag {
    /// The value of the hashtag after the # sign.
    name: String,
    /// A link to the hashtag on the instance.
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct StatusMention {
    /// The account ID of the mentioned user.
    id: String,
    /// The username of the mentioned user.
    username: String,
    /// The location of the mentioned user’s profile.
    url: String,
    /// The webfinger acct: URI of the mentioned user. Equivalent to username for local users, or username@domain for
    /// remote users.
    acct: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Application {
    name: String,
    website: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Account {
    id: String,
    username: String,
    acct: String,
    display_name: String,
    locked: bool,
    discoverable: bool,
    bot: bool,
    created_at: String,
    note: String,
    url: String,
    avatar: String,
    avatar_static: String,
    header: String,
    header_static: String,
    followers_count: u32,
    following_count: u32,
    statuses_count: u32,
    last_status_at: String,
    source: Option<CredentialsSource>,
    role: Option<Role>,
    emojis: Vec<AccountEmoji>,
    fields: Vec<AccountField>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Role {
    /// The ID of the Role in the database.
    id: Option<u32>,
    /// The name of the role.
    name: String,
    /// The hex code assigned to this role. If no hex code is assigned, the string will be empty.
    color: Option<String>,
    /// A bitmask that represents the sum of all permissions granted to the role.
    permissions: Option<u32>,
    /// Whether the role is publicly visible as a badge on user profiles.
    #[serde(default)]
    highlighted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct CredentialsSource {
    privacy: String,
    sensitive: bool,
    language: String,
    note: String,
    fields: Vec<AccountField>,
    follow_requests_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccountField {
    name: String,
    value: String,
    verified_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccountEmoji {
    shortcode: String,
    url: String,
    static_url: String,
    visible_in_picker: bool,
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

        let mastodon_client = MastodonClient::new(
            base_url,
            user_agent,
            client_name,
            website,
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
