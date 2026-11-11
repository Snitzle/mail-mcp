//! The commands a person runs in a terminal to set accounts up and check on the server.
//!
//! Signing in is done here, never by the MCP server: passwords are typed at a hidden prompt
//! and Microsoft sign-in happens in the user's own browser.

use zeroize::Zeroizing;

use crate::audit::Audit;
use crate::config::{
    APP, Account, POLICY_FILE, Paths, Provider, Settings, UserConfig, validate_account_name,
};
use crate::error::{Error, IoContext, Result};
use crate::imap::Term;
use crate::mailer::Mailer;
use crate::oauth;
use crate::sanitize::oneline;
use crate::secrets::{self, Secret};

pub const USAGE: &str = "\
mail-mcp: local email MCP server for Outlook/Hotmail and Gmail accounts

Usage:
  mail-mcp                                      run the MCP server (this is what Claude Code starts)
  mail-mcp add-outlook NAME ADDRESS CLIENT_ID   add an Outlook/Hotmail account and sign in
  mail-mcp add-gmail NAME ADDRESS               add a Gmail account (asks for an app password)
  mail-mcp auth NAME                            sign in to an Outlook account again
  mail-mcp set NAME KEY VALUE                   KEY is display_name, signature (\\n = new line),
                                                aliases (comma-separated) or save_sent_copy (true/false)
  mail-mcp read-only on|off                     switch every changing tool off or back on
  mail-mcp list                                 show accounts and the settings in force
  mail-mcp test [NAME]                          check that sign-in works for one account, or all
  mail-mcp log [N]                              show the last N audit-log entries (default 20)
  mail-mcp remove NAME                          remove an account and its stored credentials

Changes take effect the next time Claude Code starts the server.
Send limits and the folders attachments may come from are set in /etc/mail-mcp/policy.toml,
which must be owned by root. See the README.";

fn usage_error() -> Error {
    Error::invalid(USAGE)
}

fn arg(args: &[String], index: usize) -> Result<&str> {
    args.get(index).map(String::as_str).ok_or_else(usage_error)
}

pub fn run(args: &[String]) -> Result<()> {
    let paths = Paths::from_env()?;
    match arg(args, 0)? {
        "add-outlook" => add_account(
            &paths,
            arg(args, 1)?,
            arg(args, 2)?,
            Provider::Outlook,
            Some(arg(args, 3)?),
        ),
        "add-gmail" => add_account(&paths, arg(args, 1)?, arg(args, 2)?, Provider::Gmail, None),
        "auth" => auth(&paths, arg(args, 1)?),
        "set" => set(
            &paths,
            arg(args, 1)?,
            arg(args, 2)?,
            &args[3.min(args.len())..].join(" "),
        ),
        "read-only" => read_only(&paths, arg(args, 1)?),
        "list" => list(),
        "test" => test(args.get(1).map(String::as_str)),
        "log" => log(
            &paths,
            args.get(1).and_then(|n| n.parse().ok()).unwrap_or(20),
        ),
        "remove" => remove(&paths, arg(args, 1)?),
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        "version" | "--version" | "-V" => {
            println!("{APP} {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(usage_error()),
    }
}

fn find_mut<'a>(config: &'a mut UserConfig, name: &str) -> Result<&'a mut Account> {
    config
        .accounts
        .iter_mut()
        .find(|a| a.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| Error::invalid(format!("No account named '{name}'. See: mail-mcp list")))
}

fn add_account(
    paths: &Paths,
    name: &str,
    address: &str,
    provider: Provider,
    client_id: Option<&str>,
) -> Result<()> {
    validate_account_name(name)?;
    let mut config = UserConfig::load(&paths.config_file)?;
    // Re-adding an account keeps its cosmetic settings.
    let previous = config
        .accounts
        .iter()
        .position(|a| a.name.eq_ignore_ascii_case(name))
        .map(|i| config.accounts.remove(i));
    let account = Account {
        name: name.to_owned(),
        address: address.to_owned(),
        provider,
        client_id: client_id.map(str::to_owned),
        display_name: previous.as_ref().and_then(|p| p.display_name.clone()),
        signature: previous.as_ref().and_then(|p| p.signature.clone()),
        aliases: previous
            .as_ref()
            .map(|p| p.aliases.clone())
            .unwrap_or_default(),
        save_sent_copy: previous.as_ref().is_some_and(|p| p.save_sent_copy),
    };
    account.validate()?;

    match provider {
        Provider::Gmail => {
            let entered = rpassword::prompt_password(format!(
                "App password for {address} (spaces are fine): "
            ))
            .io_context("reading the app password")?;
            let password = Zeroizing::new(entered.split_whitespace().collect::<String>());
            if password.is_empty() {
                return Err(Error::invalid("No password entered"));
            }
            secrets::set(name, Secret::Password, &password)?;
        }
        Provider::Outlook => oauth::device_login(&account, |line| println!("{line}"))?,
    }
    config.accounts.push(account);
    config.save(&paths.config_file)?;
    println!("Saved account '{name}'. Checking sign-in...");
    test(Some(name))
}

fn auth(paths: &Paths, name: &str) -> Result<()> {
    let mut config = UserConfig::load(&paths.config_file)?;
    let account = find_mut(&mut config, name)?.clone();
    if account.provider != Provider::Outlook {
        return Err(Error::invalid(format!(
            "'{name}' is a Gmail account. To replace its app password run: mail-mcp add-gmail {name} {}",
            account.address
        )));
    }
    oauth::device_login(&account, |line| println!("{line}"))?;
    println!("Signed in.");
    test(Some(name))
}

fn set(paths: &Paths, name: &str, key: &str, value: &str) -> Result<()> {
    let mut config = UserConfig::load(&paths.config_file)?;
    let account = find_mut(&mut config, name)?;
    let optional = |v: String| (!v.trim().is_empty()).then_some(v);
    match key {
        "display_name" => account.display_name = optional(oneline(value, 100)),
        "signature" => account.signature = optional(value.replace("\\n", "\n")),
        "aliases" => {
            account.aliases = value
                .split(',')
                .map(str::trim)
                .filter(|a| !a.is_empty())
                .map(str::to_owned)
                .collect()
        }
        "save_sent_copy" => account.save_sent_copy = parse_switch(value)?,
        _ => {
            return Err(Error::invalid(
                "KEY must be display_name, signature, aliases or save_sent_copy",
            ));
        }
    }
    config.save(&paths.config_file)?;
    println!("Updated {name}.{key}. Restart Claude Code to apply.");
    Ok(())
}

fn parse_switch(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        _ => Err(Error::invalid("Expected on or off")),
    }
}

fn read_only(paths: &Paths, value: &str) -> Result<()> {
    let mut config = UserConfig::load(&paths.config_file)?;
    config.read_only = parse_switch(value)?;
    config.save(&paths.config_file)?;
    println!(
        "read-only is now {}. Restart Claude Code to apply.",
        if config.read_only { "ON" } else { "off" }
    );
    Ok(())
}

fn list() -> Result<()> {
    let settings = Settings::load()?;
    if settings.accounts.is_empty() {
        println!("No accounts yet. Add one with: mail-mcp add-outlook NAME ADDRESS CLIENT_ID");
    }
    for a in &settings.accounts {
        let mut extras = Vec::new();
        if let Some(name) = &a.display_name {
            extras.push(format!("display_name={name:?}"));
        }
        if !a.aliases.is_empty() {
            extras.push(format!("aliases={}", a.aliases.join(",")));
        }
        if a.signature.is_some() {
            extras.push("signature=set".to_owned());
        }
        if a.save_sent_copy {
            extras.push("save_sent_copy".to_owned());
        }
        println!(
            "{:<14} {:<8} {}  {}",
            a.name,
            a.provider.label(),
            a.address,
            extras.join(" ")
        );
    }
    let policy = &settings.policy;
    let dirs: Vec<String> = policy
        .attach_dirs
        .iter()
        .map(|d| d.display().to_string())
        .collect();
    println!();
    println!(
        "read-only:        {}",
        if settings.read_only { "ON" } else { "off" }
    );
    println!(
        "send limits:      {} per minute, {} per day, per account",
        policy.per_minute, policy.per_day
    );
    println!(
        "attach from:      {}",
        if dirs.is_empty() {
            "(nowhere)".to_owned()
        } else {
            dirs.join(", ")
        }
    );
    println!(
        "attachments save: {}",
        settings.paths.attachments_dir.display()
    );
    println!(
        "policy file:      {POLICY_FILE} ({})",
        if std::path::Path::new(POLICY_FILE).exists() {
            "in use"
        } else {
            "absent, built-in defaults apply"
        }
    );
    println!(
        "account list:     {}",
        if policy.pinned_accounts.is_empty() {
            "not pinned (see README: pinning stops a changed config from redirecting an account)"
                .to_owned()
        } else {
            format!(
                "pinned by the policy file ({} allowed)",
                policy.pinned_accounts.len()
            )
        }
    );
    println!("approval prompts: always on (cannot be switched off)");
    Ok(())
}

fn test(only: Option<&str>) -> Result<()> {
    let mailer = Mailer::new(Settings::load()?)?;
    let accounts: Vec<Account> = match only {
        Some(name) => vec![mailer.account(name)?.clone()],
        None => mailer.settings.accounts.clone(),
    };
    if accounts.is_empty() {
        println!("No accounts to test.");
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::config(format!("could not start the async runtime: {e}")))?;
    let mut failures = 0;
    for account in &accounts {
        let outcome: Result<(usize, usize)> = runtime.block_on(async {
            let mut session = mailer.session(account).await?;
            let checked = async {
                session.select("INBOX", true).await?;
                let unread = session.search(&[Term::Unseen]).await?.len();
                let folders = session.folders().await?.len();
                Ok((unread, folders))
            }
            .await;
            session.logout().await;
            checked
        });
        match outcome {
            Ok((unread, folders)) => {
                println!(
                    "OK    {} ({}): {unread} unread in inbox, {folders} folders",
                    account.name, account.address
                );
            }
            Err(e) => {
                failures += 1;
                println!("FAIL  {} ({}): {e}", account.name, account.address);
            }
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(Error::auth(format!("{failures} account(s) failed")))
    }
}

fn log(paths: &Paths, count: usize) -> Result<()> {
    for line in Audit::new(paths).tail(count)? {
        println!("{line}");
    }
    Ok(())
}

fn remove(paths: &Paths, name: &str) -> Result<()> {
    let mut config = UserConfig::load(&paths.config_file)?;
    let stored = find_mut(&mut config, name)?.name.clone();
    config.accounts.retain(|a| a.name != stored);
    config.save(&paths.config_file)?;
    secrets::delete_all(&stored)?;
    println!("Removed '{stored}' and its stored credentials.");
    Ok(())
}
