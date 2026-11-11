//! mail-mcp: a local MCP server that gives Claude Code access to the user's own mailboxes,
//! with a human approval step in front of everything that sends or destroys.

mod approval;
mod attach;
mod audit;
mod cli;
mod compose;
mod config;
mod css;
mod error;
mod fsutil;
mod harden;
mod html;
mod imap;
mod mailer;
mod message;
mod mutf7;
mod oauth;
mod ops;
mod sanitize;
mod secrets;
mod server;
#[cfg_attr(test, allow(dead_code))]
mod smtp;

use std::process::ExitCode;

fn main() -> ExitCode {
    harden::harden_process();
    let args: Vec<String> = std::env::args().skip(1).collect();
    // With no arguments we are the MCP server and stdout belongs to the protocol;
    // everything a person should read goes to stderr.
    let outcome = if args.is_empty() {
        server::run()
    } else {
        cli::run(&args)
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let text = error.to_string();
            if text.starts_with(config::APP) {
                eprintln!("{text}");
            } else {
                eprintln!("{}: {text}", config::APP);
            }
            ExitCode::FAILURE
        }
    }
}
