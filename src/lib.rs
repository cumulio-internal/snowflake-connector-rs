//! # Snowflake Connector
//!
//! A Rust client for Snowflake, which enables you to connect to Snowflake and run queries.
//!
//! ```rust
//! # use snowflake_connector_rs::{Result, SnowflakeAuthMethod, SnowflakeClient, SnowflakeClientConfig, AccountLocator};
//! # async fn run() -> Result<()> {
//! let client = SnowflakeClient::new(
//!     "USERNAME",
//!     SnowflakeAuthMethod::Password("PASSWORD".to_string()),
//!     SnowflakeClientConfig {
//!         account: AccountLocator::ShortName("ACCOUNT".to_string()),
//!         role: Some("ROLE".to_string()),
//!         warehouse: Some("WAREHOUSE".to_string()),
//!         database: Some("DATABASE".to_string()),
//!         schema: Some("SCHEMA".to_string()),
//!         timeout: Some(std::time::Duration::from_secs(30)),
//!     },
//! )?;
//! let session = client.create_session().await?;
//!
//! let query = "CREATE TEMPORARY TABLE example (id NUMBER, value STRING)";
//! session.query(query).await?;
//!
//! let query = "INSERT INTO example (id, value) VALUES (1, 'hello'), (2, 'world')";
//! session.query(query).await?;
//!
//! let query = "SELECT * FROM example ORDER BY id";
//! let rows = session.query(query).await?;
//! assert_eq!(rows.len(), 2);
//! assert_eq!(rows[0].get::<i64>("ID")?, 1);
//! assert_eq!(rows[0].get::<String>("VALUE")?, "hello");
//! # Ok(())
//! # }
//! ```

mod auth;
mod chunk;
mod error;
mod query;
mod row;
mod session;

use std::time::Duration;
use url::Url;

pub use error::{Error, Result};
pub use query::QueryExecutor;
pub use row::{SnowflakeColumn, SnowflakeColumnType, SnowflakeDecode, SnowflakeRow};
pub use session::SnowflakeSession;

use auth::login;

use reqwest::{Client, ClientBuilder, Proxy};

/// Represents a way to identify a Snowflake account.
///
/// This enum provides two different formats for specifying an account:
/// - `ShortName`: A short identifier, typically including the account name and region.
/// - `FullUrl`: A complete URL pointing to the account.
#[derive(Debug, Clone)]
pub enum AccountLocator {
    /// Your Snowflake account (without the .snowflakecomputing.com suffix). This should have the format eg. TO12345.eu-west-1 or TO12345.us-east-2.aws on AWS or TO12345.west-europe.azure on Azure
    ShortName(String),
    /// The full account url e.g., "https://TO12345.eu-west-1.gcp.snowflakecomputing.com"
    FullUrl(Url),
}

impl Default for AccountLocator {
    fn default() -> Self {
        AccountLocator::ShortName("".to_string())
    }
}

#[derive(Clone)]
pub struct SnowflakeClient {
    http: Client,

    username: String,
    auth: SnowflakeAuthMethod,
    config: SnowflakeClientConfig,
}

#[derive(Default, Clone)]
pub struct SnowflakeClientConfig {
    pub account: AccountLocator,

    pub warehouse: Option<String>,
    pub database: Option<String>,
    pub schema: Option<String>,
    pub role: Option<String>,
    pub timeout: Option<Duration>,
}

#[derive(Clone)]
pub enum SnowflakeAuthMethod {
    Password(String),
    KeyPair {
        encrypted_pem: String,
        password: Vec<u8>,
    },
}

impl SnowflakeClient {
    pub fn new(
        username: &str,
        auth: SnowflakeAuthMethod,
        config: SnowflakeClientConfig,
    ) -> Result<Self> {
        let client = ClientBuilder::new().gzip(true).use_rustls_tls().build()?;
        Ok(Self {
            http: client,
            username: username.to_string(),
            auth,
            config,
        })
    }

    pub fn with_proxy(self, host: &str, port: u16, username: &str, password: &str) -> Result<Self> {
        let proxy = Proxy::all(format!("http://{}:{}", host, port).as_str())?
            .basic_auth(username, password);

        let client = ClientBuilder::new()
            .gzip(true)
            .use_rustls_tls()
            .proxy(proxy)
            .build()?;
        Ok(Self {
            http: client,
            username: self.username,
            auth: self.auth,
            config: self.config,
        })
    }

    pub async fn create_session(&self) -> Result<SnowflakeSession> {
        let login_response = login(&self.http, &self.username, &self.auth, &self.config).await?;
        Ok(SnowflakeSession {
            http: self.http.clone(),
            base_url: login_response.base_url,
            session_token: login_response.token,
            timeout: self.config.timeout,
        })
    }
}
