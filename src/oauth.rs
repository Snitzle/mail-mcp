//! Microsoft sign-in for Outlook.com / Hotmail accounts.
//!
//! Outlook.com no longer accepts passwords over IMAP or SMTP, so we use OAuth 2.0:
//! the user signs in once in a browser (device-code flow) and we keep the resulting
//! refresh token in the keyring. Access tokens are short-lived and held only in memory.
//!
//! The HTTP calls here block. `device_login` is for the CLI; the server goes through
//! [`TokenCache`], which moves the blocking work off the async runtime.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::config::{APP, Account};
use crate::error::{Error, Result};
use crate::secrets::{self, Secret};

/// The `consumers` tenant is personal Microsoft accounts only (hotmail.com, outlook.com,
/// live.com, ...). Endpoints are fixed so tokens are only ever sent to Microsoft.
const DEVICE_CODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const TOKEN_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
/// Mail over IMAP and SMTP for the signed-in user, plus a refresh token. Nothing else.
const SCOPES: &str = "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
/// Refresh this long before the token actually expires.
const EXPIRY_MARGIN: Duration = Duration::from_secs(120);

#[derive(Debug, Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
}

/// Microsoft answers the token endpoint with either tokens or an error, both as JSON.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
}

struct AccessToken {
    token: Zeroizing<String>,
    expires_at: Instant,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(APP)
        .build()
        .new_agent()
}

fn post_form<T: serde::de::DeserializeOwned>(
    agent: &ureq::Agent,
    url: &str,
    form: &[(&str, &str)],
) -> Result<T> {
    let mut response = agent
        .post(url)
        .send_form(form.iter().copied())
        .map_err(|e| Error::Network(format!("contacting Microsoft sign-in: {e}")))?;
    response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_json()
        .map_err(|e| Error::Network(format!("unexpected reply from Microsoft sign-in: {e}")))
}

fn client_id(account: &Account) -> Result<&str> {
    account
        .client_id
        .as_deref()
        .ok_or_else(|| Error::config(format!("account '{}' has no client_id", account.name)))
}

fn describe(response: &TokenResponse) -> String {
    let code = response.error.as_deref().unwrap_or("unknown_error");
    match response.error_description.as_deref() {
        // Microsoft's descriptions run to several lines of trace IDs; the first is the useful one.
        Some(text) => format!("{code}: {}", text.lines().next().unwrap_or_default()),
        None => code.to_owned(),
    }
}

/// Ask Microsoft for a device code. A wrong or misconfigured client ID is reported here,
/// with Microsoft's own explanation.
fn request_device_code(agent: &ureq::Agent, client_id: &str) -> Result<DeviceCode> {
    let reply: serde_json::Value = post_form(
        agent,
        DEVICE_CODE_URL,
        &[("client_id", client_id), ("scope", SCOPES)],
    )?;
    if let Some(code) = reply.get("error").and_then(|e| e.as_str()) {
        let detail = reply
            .get("error_description")
            .and_then(|d| d.as_str())
            .and_then(|d| d.lines().next())
            .unwrap_or_default();
        return Err(Error::auth(format!(
            "Microsoft would not start sign-in ({code}: {detail}). Check the client ID, that the app allows personal Microsoft accounts, and that \"Allow public client flows\" is switched on."
        )));
    }
    serde_json::from_value(reply)
        .map_err(|e| Error::Network(format!("unexpected reply from Microsoft sign-in: {e}")))
}

/// Sign in interactively. `show` is given the lines to display to the user.
pub fn device_login(account: &Account, mut show: impl FnMut(&str)) -> Result<()> {
    let agent = agent();
    let client_id = client_id(account)?;
    let code = request_device_code(&agent, client_id)?;

    show(&format!(
        "To sign in, open {} and enter the code {}",
        code.verification_uri, code.user_code
    ));
    show(&format!("Sign in as {}.", account.address));
    show(
        "Only enter this code because YOU just ran this command. Never enter a code someone sent you.",
    );

    let deadline = Instant::now() + Duration::from_secs(code.expires_in.min(900));
    let mut interval = Duration::from_secs(code.interval.unwrap_or(5).clamp(1, 30));
    loop {
        std::thread::sleep(interval);
        if Instant::now() >= deadline {
            return Err(Error::auth(
                "the sign-in code expired before it was used; run the command again",
            ));
        }
        let response: TokenResponse = post_form(
            &agent,
            TOKEN_URL,
            &[
                ("grant_type", DEVICE_GRANT),
                ("client_id", client_id),
                ("device_code", &code.device_code),
            ],
        )?;
        match response.error.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += Duration::from_secs(5),
            Some(_) => {
                return Err(Error::auth(format!(
                    "sign-in failed: {}",
                    describe(&response)
                )));
            }
            None => {
                let refresh = response.refresh_token.as_deref().ok_or_else(|| {
                    Error::auth("Microsoft did not return a refresh token (the offline_access permission is missing)")
                })?;
                return secrets::set(&account.name, Secret::RefreshToken, refresh);
            }
        }
    }
}

/// Exchange the stored refresh token for a new access token (blocking).
fn refresh(account: &Account) -> Result<AccessToken> {
    let sign_in_again = || {
        Error::auth(format!(
            "Outlook sign-in for '{name}' has expired or was never completed. The user must run in a terminal: mail-mcp auth {name}",
            name = account.name
        ))
    };
    let stored = secrets::get(&account.name, Secret::RefreshToken)?.ok_or_else(sign_in_again)?;
    let response: TokenResponse = post_form(
        &agent(),
        TOKEN_URL,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", client_id(account)?),
            ("refresh_token", stored.as_str()),
            ("scope", SCOPES),
        ],
    )?;
    if matches!(
        response.error.as_deref(),
        Some("invalid_grant" | "interaction_required")
    ) {
        return Err(sign_in_again());
    }
    let (None, Some(token)) = (response.error.as_deref(), response.access_token.as_deref()) else {
        return Err(Error::auth(format!(
            "could not refresh the Outlook sign-in for '{}': {}",
            account.name,
            describe(&response)
        )));
    };
    // Microsoft rotates refresh tokens; keep the newest so sign-in stays alive.
    if let Some(rotated) = response.refresh_token.as_deref()
        && rotated != stored.as_str()
    {
        secrets::set(&account.name, Secret::RefreshToken, rotated)?;
    }
    let lifetime = Duration::from_secs(response.expires_in.unwrap_or(3600));
    Ok(AccessToken {
        token: Zeroizing::new(token.to_owned()),
        expires_at: Instant::now() + lifetime,
    })
}

/// Access tokens for the running server, refreshed on demand.
#[derive(Default)]
pub struct TokenCache {
    /// Held across a refresh so two tool calls never refresh the same account at once
    /// (the second would present a refresh token the first had just rotated away).
    tokens: tokio::sync::Mutex<HashMap<String, AccessToken>>,
}

impl TokenCache {
    pub async fn access_token(&self, account: &Account) -> Result<Zeroizing<String>> {
        let mut tokens = self.tokens.lock().await;
        if let Some(cached) = tokens.get(&account.name)
            && cached.expires_at > Instant::now() + EXPIRY_MARGIN
        {
            return Ok(cached.token.clone());
        }
        let owned = account.clone();
        let fresh = tokio::task::spawn_blocking(move || refresh(&owned))
            .await
            .map_err(|e| Error::auth(format!("token refresh task failed: {e}")))??;
        let token = fresh.token.clone();
        tokens.insert(account.name.clone(), fresh);
        Ok(token)
    }

    /// Forget a token the server rejected, so the next call fetches a new one.
    pub async fn forget(&self, account: &Account) {
        self.tokens.lock().await.remove(&account.name);
    }
}

/// The SASL XOAUTH2 initial response for `address` (before base64).
pub fn xoauth2_payload(address: &str, access_token: &str) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "user={address}\x01auth=Bearer {access_token}\x01\x01"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live check of the HTTPS client against Microsoft: `cargo test -- --ignored`.
    #[test]
    #[ignore = "contacts login.microsoftonline.com"]
    fn microsoft_rejects_an_unknown_client_id_with_a_readable_error() {
        let error = request_device_code(&agent(), "00000000-0000-0000-0000-000000000000")
            .expect_err("must fail");
        let text = error.to_string();
        assert!(
            text.starts_with("Microsoft would not start sign-in"),
            "{text}"
        );
    }

    #[test]
    fn xoauth2_payload_has_the_documented_shape() {
        assert_eq!(
            xoauth2_payload("me@hotmail.com", "tok").as_str(),
            "user=me@hotmail.com\x01auth=Bearer tok\x01\x01"
        );
    }

    #[test]
    fn error_descriptions_are_cut_to_one_line() {
        let response = TokenResponse {
            access_token: None,
            refresh_token: None,
            expires_in: None,
            error: Some("invalid_grant".into()),
            error_description: Some(
                "AADSTS70000: The grant is expired.\r\nTrace ID: abc\r\nCorrelation ID: def".into(),
            ),
        };
        assert_eq!(
            describe(&response),
            "invalid_grant: AADSTS70000: The grant is expired."
        );
    }

    #[test]
    fn token_error_and_success_both_deserialize() {
        let pending: TokenResponse =
            serde_json::from_str(r#"{"error":"authorization_pending","error_description":"x"}"#)
                .expect("pending");
        assert_eq!(pending.error.as_deref(), Some("authorization_pending"));
        let ok: TokenResponse = serde_json::from_str(
            r#"{"token_type":"Bearer","scope":"s","expires_in":3599,"access_token":"a","refresh_token":"r"}"#,
        )
        .expect("ok");
        assert_eq!(
            (
                ok.access_token.as_deref(),
                ok.refresh_token.as_deref(),
                ok.expires_in
            ),
            (Some("a"), Some("r"), Some(3599))
        );
    }
}
