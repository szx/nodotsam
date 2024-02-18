use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct HomeTimeline {
    pub statuses: Vec<Status>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FilterResult {
    /// The filter that was matched
    pub filter: Filter,
    /// The keyword within the filter that was matched.
    pub keyword_matches: Option<Vec<String>>,
    /// The status ID within the filter that was matched.
    pub status_matches: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FilterStatus {
    /// The ID of the FilterStatus in the database.
    pub id: String,
    /// The ID of the Status that will be filtered.
    pub status_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FilterKeyword {
    /// The ID of the FilterKeyword in the database.
    pub id: String,
    /// The phrase to be matched against.
    pub keyword: String,
    /// Should the filter consider word boundaries?
    pub whole_word: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PollOption {
    /// The text value of the poll option.
    pub title: String,
    /// The total number of received votes for this option.
    pub votes_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StatusTag {
    /// The value of the hashtag after the # sign.
    pub name: String,
    /// A link to the hashtag on the instance.
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Application {
    /// The name of your application.
    pub name: String,
    /// The website associated with your application.
    pub website: Option<String>,
    /// Client ID key, to be used for obtaining OAuth tokens
    pub client_id: Option<String>,
    /// Client secret key, to be used for obtaining OAuth tokens
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    /// The account id.
    pub id: String,
    /// The username of the account, not including domain.
    pub username: String,
    /// The Webfinger account URI. Equal to username for local users, or username@domain for remote users.
    pub acct: String,
    /// The location of the user’s profile page.
    pub url: String,
    /// The profile’s display name.
    pub display_name: String,
    /// Whether the account manually approves follow requests.
    pub locked: bool,
    /// Whether the account has opted into discovery features such as the profile directory.
    pub discoverable: Option<bool>,
    /// Indicates that the account may perform automated actions, may not be monitored, or identifies as a robot.
    pub bot: bool,
    /// When the account was created. (ISO 8601 Datetime)
    pub created_at: String,
    /// The profile’s bio or description.
    pub note: String,
    /// An image icon that is shown next to statuses and in the profile.
    pub avatar: String,
    /// A static version of the avatar. Equal to avatar if its value is a static image; different if avatar is an animated GIF.
    pub avatar_static: String,
    /// An image banner that is shown above the profile and in profile cards.
    pub header: String,
    /// A static version of the header. Equal to header if its value is a static image; different if header is an animated GIF.
    pub header_static: String,
    /// The reported followers of this profile.
    pub followers_count: u32,
    /// The reported follows of this profile.
    pub following_count: u32,
    /// How many statuses are attached to this account.
    pub statuses_count: u32,
    /// When the most recent status was posted.
    pub last_status_at: Option<String>,
    /// An extra attribute that contains source values to be used with API methods that verify credentials and update credentials.
    pub source: Option<CredentialsSource>,
    /// The role assigned to the currently authorized user.
    pub role: Option<Role>,
    /// Custom emoji entities to be used when rendering the profile.
    pub emojis: Vec<CustomEmoji>,
    /// Additional metadata attached to a profile as name-value pairs.
    pub fields: Vec<AccountField>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialsSource {
    /// The default post privacy to be used for new statuses.
    pub privacy: String,
    /// Whether new statuses should be marked sensitive by default.
    pub sensitive: bool,
    ///  The default posting language for new statuses.
    pub language: String,
    /// Profile bio, in plain-text instead of in HTML.
    pub note: String,
    /// Metadata about the account.
    pub fields: Vec<AccountField>,
    /// The number of pending follow requests.
    pub follow_requests_count: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountField {
    /// The key of a given field’s key-value pair.
    pub name: String,
    /// The value associated with the name key.
    pub value: String,
    /// imestamp of when the server verified a URL value for a rel=“me” link.
    pub verified_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreatedApplication {
    pub id: String,
    pub redirect_uri: String,

    #[serde(flatten)]
    pub application: Application,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Token {
    /// An OAuth token to be used for authorization.
    pub access_token: String,
    /// When the token was generated. (UNIX Timestamp)
    pub created_at: u32,
    /// The OAuth scopes granted by this token, space-separated.
    pub scope: String,
    /// The OAuth token type. Mastodon uses Bearer tokens.
    pub token_type: String,
}
