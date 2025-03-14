mod key_pair;

use chrono::Utc;
use pkcs8::DecodePrivateKey;
use reqwest::Client;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};

use crate::{AccountLocator, Error, Result, SnowflakeAuthMethod, SnowflakeClientConfig};

use self::key_pair::generate_jwt_from_key_pair;

pub struct InternalLoginResponse {
    pub token: String,
    pub base_url: String,
}

/// Login to Snowflake and return a session token and base URL.
pub(super) async fn login(
    http: &Client,
    username: &str,
    auth: &SnowflakeAuthMethod,
    config: &SnowflakeClientConfig,
) -> Result<InternalLoginResponse> {
    let (base_url, account) = match &config.account {
        AccountLocator::ShortName(account) => (
            format!("https://{account}.snowflakecomputing.com"),
            account.clone(),
        ),
        AccountLocator::FullUrl(url) => {
            let host = url.host_str().ok_or(Error::AccountUrlParseError(
                "No host found in URL".to_string(),
            ))?;

            // This is only the first part of the account
            let account = host
                .split('.')
                .next()
                .ok_or(Error::AccountUrlParseError(
                    "Could not extract account name from URL".to_string(),
                ))?
                .to_string();

            let mut base_url = url.to_string();
            if base_url.ends_with('/') {
                base_url.pop(); // Remove the trailing slash if any
            }
            (base_url, account)
        }
    };

    println!("base_url: {}, account: {}", base_url, account);
    let login_url = format!("{base_url}/session/v1/login-request");

    let mut queries = vec![];
    if let Some(warehouse) = &config.warehouse {
        queries.push(("warehouse", warehouse));
    }
    if let Some(database) = &config.database {
        queries.push(("databaseName", database));
    }
    if let Some(schema) = &config.schema {
        queries.push(("schemaName", schema));
    }
    if let Some(role) = &config.role {
        queries.push(("roleName", role));
    }

    let login_data = login_request_data(username, auth, &account)?;
    let response = http
        .post(login_url)
        .query(&queries)
        .json(&json!({
            "data": login_data
        }))
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(Error::Communication(body));
    }

    let response: Response = serde_json::from_str(&body).map_err(|_| Error::Communication(body))?;
    if !response.success {
        return Err(Error::Communication(response.message.unwrap_or_default()));
    }

    Ok(InternalLoginResponse {
        token: response.data.token,
        base_url,
    })
}

fn login_request_data(username: &str, auth: &SnowflakeAuthMethod, account: &str) -> Result<Value> {
    println!("username: {}, account: {}", username, account);
    match auth {
        SnowflakeAuthMethod::Password(password) => Ok(json!({
            "LOGIN_NAME": username,
            "PASSWORD": password,
            "ACCOUNT_NAME": account
        })),
        SnowflakeAuthMethod::KeyPair {
            encrypted_pem,
            password,
        } => {
            let private_key = match password.len() {
                0 => RsaPrivateKey::from_pkcs8_pem(&encrypted_pem)?,
                _ => RsaPrivateKey::from_pkcs8_encrypted_pem(encrypted_pem, password)?,
            };

            let jwt =
                generate_jwt_from_key_pair(private_key, username, account, Utc::now().timestamp())?;
            Ok(json!({
                "LOGIN_NAME": username,
                "ACCOUNT_NAME": account,
                "TOKEN": jwt,
                "AUTHENTICATOR": "SNOWFLAKE_JWT"
            }))
        }
    }
}

#[derive(serde::Deserialize)]
struct LoginResponse {
    token: String,
}

#[derive(serde:: Deserialize)]
struct Response {
    data: LoginResponse,
    message: Option<String>,
    success: bool,
}
