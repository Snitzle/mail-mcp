//! The pieces every mail operation needs: settings, sign-in, connections, the audit log
//! and the send limiter.

use std::sync::Arc;

use serde_json::json;
use tokio_rustls::rustls::ClientConfig;

use crate::audit::{Audit, SendLimiter};
use crate::config::{Account, Provider, Settings};
use crate::error::{Error, Result};
use crate::imap::{self, Credentials, Session};
use crate::oauth::TokenCache;
use crate::secrets::{self, Secret};
#[cfg(not(test))]
use crate::smtp;

pub struct Mailer {
    pub settings: Settings,
    pub audit: Audit,
    pub limiter: SendLimiter,
    tokens: TokenCache,
    tls: Arc<ClientConfig>,
    /// In unit tests nothing goes to the network: messages that would have been sent are
    /// collected here as (envelope recipients, bytes).
    #[cfg(test)]
    pub outbox: std::sync::Mutex<Vec<(Vec<String>, Vec<u8>)>>,
}

impl Mailer {
    pub fn new(settings: Settings) -> Result<Self> {
        Ok(Self {
            audit: Audit::new(&settings.paths),
            limiter: SendLimiter::load(&settings.paths, &settings.policy),
            tokens: TokenCache::default(),
            tls: imap::tls_config()?,
            settings,
            #[cfg(test)]
            outbox: std::sync::Mutex::default(),
        })
    }

    pub fn account(&self, name: &str) -> Result<&Account> {
        self.settings.account(name)
    }

    async fn credentials(&self, account: &Account) -> Result<Credentials> {
        match account.provider {
            Provider::Outlook => Ok(Credentials::AccessToken(
                self.tokens.access_token(account).await?,
            )),
            Provider::Gmail => {
                let name = account.name.clone();
                let stored =
                    tokio::task::spawn_blocking(move || secrets::get(&name, Secret::Password))
                        .await
                        .map_err(|e| Error::Keyring(e.to_string()))??;
                stored.map(Credentials::Password).ok_or_else(|| {
                    Error::auth(format!(
                        "No app password is stored for '{name}'. The user must run in a terminal: mail-mcp add-gmail {name} {}",
                        account.address,
                        name = account.name
                    ))
                })
            }
        }
    }

    /// Open an authenticated IMAP session. A rejected Outlook token is refreshed once.
    pub async fn session(&self, account: &Account) -> Result<Session> {
        let first =
            Session::connect(account, self.credentials(account).await?, self.tls.clone()).await;
        match first {
            Err(Error::Auth(_)) if account.provider == Provider::Outlook => {
                self.tokens.forget(account).await;
                Session::connect(account, self.credentials(account).await?, self.tls.clone()).await
            }
            other => other,
        }
    }

    /// Send a finished message. Counts against the send limit and is always logged.
    pub async fn send(
        &self,
        account: &Account,
        recipients: &[String],
        raw: &[u8],
        via: &str,
        subject: &str,
        message_id: &str,
    ) -> Result<()> {
        self.limiter.reserve(&account.name)?;
        #[cfg(not(test))]
        let outcome = match self.credentials(account).await {
            Ok(credentials) => smtp::send(account, &credentials, recipients, raw).await,
            Err(e) => Err(e),
        };
        #[cfg(test)]
        let outcome: Result<()> = {
            let mut outbox = self
                .outbox
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            outbox.push((recipients.to_vec(), raw.to_vec()));
            Ok(())
        };
        self.audit.record(
            if outcome.is_ok() {
                "send"
            } else {
                "send_failed"
            },
            &account.name,
            json!({
                "via": via,
                "to": recipients,
                "subject": subject,
                "message_id": message_id,
                "error": outcome.as_ref().err().map(ToString::to_string),
            }),
        );
        outcome
    }
}
