//! Handing a finished message to the provider's SMTP server.

use std::time::Duration;

use lettre::address::Envelope;
use lettre::transport::smtp::authentication::{Credentials as SmtpCredentials, Mechanism};
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

use crate::config::{Account, SmtpSecurity};
use crate::error::{Error, Result};
use crate::imap::Credentials;

const SMTP_TIMEOUT: Duration = Duration::from_secs(60);
/// A little above the 25 MB attachment limit once base64 has inflated it.
const MAX_MESSAGE_BYTES: usize = 40 * 1024 * 1024;

fn smtp_error(e: impl std::fmt::Display) -> Error {
    Error::Smtp(e.to_string())
}

/// Send `raw` to exactly `recipients`. The envelope is given explicitly, so nothing in the
/// message's own headers can add or change who receives it.
pub async fn send(
    account: &Account,
    credentials: &Credentials,
    recipients: &[String],
    raw: &[u8],
) -> Result<()> {
    if raw.len() > MAX_MESSAGE_BYTES {
        return Err(Error::invalid("That message is too large to send"));
    }
    let (host, port, security) = account.provider.smtp();
    // Both constructors verify the server certificate. With STARTTLS the upgrade is
    // required: if the server does not offer it, nothing is sent in the clear.
    let builder = match security {
        SmtpSecurity::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(host),
        SmtpSecurity::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host),
    }
    .map_err(smtp_error)?;
    let (secret, mechanism) = match credentials {
        Credentials::Password(password) => (password.as_str(), Mechanism::Plain),
        Credentials::AccessToken(token) => (token.as_str(), Mechanism::Xoauth2),
    };
    let transport = builder
        .port(port)
        .credentials(SmtpCredentials::new(
            account.address.clone(),
            secret.to_owned(),
        ))
        .authentication(vec![mechanism])
        .timeout(Some(SMTP_TIMEOUT))
        .build();

    let parse = |address: &str| {
        address
            .parse::<Address>()
            .map_err(|e| Error::invalid(format!("'{address}': {e}")))
    };
    let to = recipients
        .iter()
        .map(|r| parse(r))
        .collect::<Result<Vec<_>>>()?;
    let envelope = Envelope::new(Some(parse(&account.address)?), to).map_err(smtp_error)?;

    match tokio::time::timeout(SMTP_TIMEOUT * 3, transport.send_raw(&envelope, raw)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(smtp_error(e)),
        Err(_) => Err(Error::Timeout("sending the message")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Provider;

    /// Live check that both providers' SMTP servers complete a verified TLS handshake
    /// (STARTTLS for Outlook, TLS from the start for Gmail). No sign-in is attempted and
    /// nothing is sent. Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "contacts the Outlook and Gmail SMTP servers"]
    async fn smtp_servers_pass_tls_verification() {
        for provider in [Provider::Outlook, Provider::Gmail] {
            let (host, port, security) = provider.smtp();
            let builder = match security {
                SmtpSecurity::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(host),
                SmtpSecurity::StartTls => {
                    AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                }
            }
            .expect("builder");
            let transport: AsyncSmtpTransport<Tokio1Executor> =
                builder.port(port).timeout(Some(SMTP_TIMEOUT)).build();
            let connected = transport.test_connection().await;
            assert!(matches!(connected, Ok(true)), "{provider:?}: {connected:?}");
        }
    }
}
