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

    fn verify_authorize(&self) -> Result<(), MastodonClientError> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(&self.user_agent)
            .build()?;

        let _response = client
            .get(r#"https://fedi.sszczyrb.dev/api/v1/accounts/verify_credentials"#)
            .bearer_auth(&self.access_token)
            .send()?;
        // TODO: Return parsed response.
        Ok(())
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

        mastodon_client.verify_authorize().unwrap();
        // TODO: /api/v1/timelines/home
    }
}
