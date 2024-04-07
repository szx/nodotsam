pub mod protocol;

use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

const REDIRECT_URI: &str = "urn:ietf:wg:oauth:2.0:oob";
const SCOPES: &str = "read write follow";

#[derive(Debug)]
pub struct MastodonClient {
    pub base_url: String,
    pub user_agent: String,
    pub client_name: String,
    pub website: String,

    pub access_token: String,
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

    pub fn favourite(&self, id: &str) -> Result<protocol::Status, MastodonClientError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(&self.user_agent)
            .build()?;

        let response = client
            .post(format!(r"{}/api/v1/statuses/{id}/favourite", self.base_url))
            .bearer_auth(&self.access_token)
            .send()?
            .text()?;

        Ok(serde_json::from_str(&response)?)
    }

    pub fn authorize(
        &mut self,
        cached_access_token: Option<impl Into<String>>,
        get_authorization_code_callback: GetAuthorizationCodeCallback,
    ) -> Result<(), MastodonClientError> {
        if self.access_token.is_empty() {
            self.access_token = cached_access_token
                .map(|x| Ok(x.into()))
                .unwrap_or_else(|| {
                    Self::login(
                        self.base_url.as_str(),
                        self.user_agent.as_str(),
                        self.client_name.as_str(),
                        self.website.as_str(),
                        get_authorization_code_callback,
                    )
                })?;
        }
        Ok(())
    }

    pub fn home_timeline(&self) -> Result<protocol::HomeTimeline, MastodonClientError> {
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

    pub fn verify_credentials(&self) -> Result<protocol::Account, MastodonClientError> {
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
        let create_app = || -> Result<protocol::CreatedApplication, MastodonClientError> {
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

        let request_access_token = |client_id: &str,
                                    client_secret: &str,
                                    authorization_code: &str|
         -> Result<protocol::Token, MastodonClientError> {
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
                .send()?
                .text()?;
            Ok(serde_json::from_str(&response)?)
        };

        let response = create_app()?;

        let client_id = response
            .application
            .client_id
            .ok_or(MastodonClientError::MissingField("client_id".into()))?;
        let client_secret = response
            .application
            .client_secret
            .ok_or(MastodonClientError::MissingField("client_id".into()))?;

        let login_url = get_login_url(&client_id);
        let authorization_code = get_authorization_code_callback(login_url.as_str())?;
        let authorization_code = authorization_code.trim();

        let response = request_access_token(&client_id, &client_secret, authorization_code)?;
        Ok(response.access_token)
    }
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
    #[error("missing field: {0}")]
    MissingField(String),
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
                std::env::var("NODOTSAM_TEST_ACCESS_TOKEN").ok(),
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
        assert_ne!(mastodon_client.access_token, "");

        mastodon_client.verify_credentials().unwrap();
        mastodon_client.home_timeline().unwrap();
    }
}
