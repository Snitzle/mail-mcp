# mail-mcp

A local [MCP](https://modelcontextprotocol.io) server, written in Rust, that lets an AI
assistant such as Claude Code work with your own mailboxes: Outlook.com / Hotmail and
Gmail, several accounts at once.

It is built on one idea: **an assistant that can read your mail is reading text written by
strangers, so it must not be able to do anything irreversible on its own.** Sending,
deleting and uploading files all stop at a dialog that you, not the assistant, answer.

- One binary, about 7 MB. No runtime, no background service, no cloud component.
- Talks only to Microsoft's and Google's own mail servers, over verified TLS.
- Credentials live in your desktop keyring, never in a file.
- Linux only, for now.

## Status

Early. Use it knowing what has and has not been proven:

| | |
|---|---|
| Signing in, listing, searching and reading on a real Outlook.com mailbox | Works |
| The approval gate, message composition, HTML handling, file handling | Covered by 120 automated tests |
| Sending, moving and drafting against a real mailbox | Not yet exercised |
| Gmail against a real mailbox | Not yet exercised |

## What it can do

| Tool | What it does | Asks you first? |
|---|---|---|
| `list_accounts`, `list_folders` | Show accounts and folders | No |
| `search_emails`, `read_email`, `get_thread` | Find and read mail (never marks it read) | No |
| `mark_email` | Read/unread, star/unstar | No |
| `categorize_emails`, `create_folder` | Gmail labels, Outlook folders | No |
| `save_attachments` | Save into `~/Downloads/mail-attachments` only | No |
| `create_draft` | Save a draft; nothing is sent | Only if it attaches files from your disk |
| `move_email` | Move within an account | Only when the destination is trash or spam |
| `send_email`, `send_draft` | Send | Always |
| `copy_to_account` | Copy mail to another of your accounts | Always |

## How it protects you

**Approval is built in and cannot be switched off.** Every send, every cross-account copy,
every move to trash or spam and every upload of a local file shows a dialog with the real
recipient addresses, the subject, the attachments (with the path each came from) and the
text. You tick a box to allow it. If the dialog cannot be shown, or you do anything other
than tick the box, nothing happens. What is executed is the exact thing the dialog
described, held in memory between the dialog and the action; it is never rebuilt from the
request, so it cannot change after you approve it.

**Email content is treated as hostile.** Text that came from an email has invisible
characters stripped. HTML is parsed the way a browser parses it, and text hidden from a
human reader (inline styles, the `hidden` attribute, `<style>` rules) is removed and
reported. Links are shown with the host they really go to. Failed sender authentication
(SPF, DKIM, DMARC), Reply-To redirection and display names posing as another address are
turned into warnings.

**The settings that matter are out of the assistant's reach.** Send limits and the folders
attachments may come from live in `/etc/mail-mcp/policy.toml`, which is only honoured when
root owns it. The binary is installed root-owned. Your own config file can only list
accounts and switch read-only mode on. The mail server addresses are compiled in.

**Nothing leaves the lines.** Outgoing mail is plain text. Recipients are parsed once, and
that one list is the message header, the delivery envelope and the dialog. Attachments are
read only from allowed folders, never hidden files, and are opened in a way the kernel
guarantees involves no symbolic link. Saved attachments go to one private folder, are
never executable and never overwrite anything. Every change is written to an audit log and
to the system journal.

### What it cannot protect you from

- **An assistant with a shell runs as you.** It could ask the desktop keyring for the
  stored credentials directly, or point its host at a different program. The deny rules
  below make that harder; they do not make it impossible. Real isolation means running
  the assistant as a different user.
- **Hidden-text detection is a heuristic.** White text on a white background inherited
  from a parent element, text inside images and similar tricks are not caught. The absence
  of a warning does not mean an email is clean.
- **Reading is not gated.** An email that manipulates the assistant could get it to read
  other mail and leak it through a tool that has nothing to do with mail-mcp, such as a
  shell command or a web request. Use read-only mode, and your assistant's own permission
  prompts, when you let it loose on an inbox.
- **You are the last check.** Read the dialog, especially the recipient addresses.

## Requirements

- Linux with a desktop keyring that speaks the Secret Service API (KDE Wallet, GNOME
  Keyring).
- Rust 1.98 or newer to build.
- An MCP client that shows elicitation dialogs to a person. Claude Code in a terminal
  does. Hosts that answer those dialogs automatically (some SDK-based or headless hosts)
  will find every gated action refused, which is the intended behaviour: reading still
  works there, sending and deleting do not.

## Install

```sh
git clone https://github.com/Snitzle/mail-mcp
cd mail-mcp
cargo build --release
sudo sh scripts/install-root.sh        # /usr/local/bin/mail-mcp and /etc/mail-mcp/policy.toml
claude mcp add --scope user mail /usr/local/bin/mail-mcp
```

Run the setup commands below by their full path, `/usr/local/bin/mail-mcp`, so you always
run the root-owned binary.

## Add an Outlook.com / Hotmail account

Outlook.com no longer accepts passwords from mail programs. You sign in through Microsoft
once and mail-mcp keeps a refresh token in your keyring. Microsoft requires every program
that does this to identify itself with an application (client) ID, and mail-mcp does not
ship with one: you register your own, which is free.

1. Registering needs a Microsoft Entra directory. A personal Microsoft account does not
   have one by default, and signing in to the Entra admin centre without one fails with
   *"account does not exist in tenant 'Microsoft Services'"*. Creating a free Azure
   account at <https://azure.microsoft.com/free> with the same Microsoft account gives
   you a directory.
2. At <https://entra.microsoft.com> go to **Applications → App registrations → New
   registration**. Name it anything. Under **Supported account types** choose **Personal
   Microsoft accounts only**. Leave the redirect URI empty.
3. On the app's **Authentication** page set **Allow public client flows** to **Yes**.
4. Copy the **Application (client) ID** from the **Overview** page.

No client secret and no API permissions are needed. The permissions (IMAP and SMTP for
your own mailbox, nothing else) are requested when you sign in, and you approve them then.

```sh
/usr/local/bin/mail-mcp add-outlook hotmail you@hotmail.com <client-id>
```

It prints a short code and a Microsoft web address. Open the address, enter the code, sign
in as that mailbox and approve. The command then checks that it can open your inbox.

**If the check fails with "User is authenticated but not connected"**, Microsoft accepted
your sign-in but refused to open the mailbox. Two causes account for nearly all cases:

- The address you gave is not exactly the mailbox's own address (for example
  `@hotmail.com` when the mailbox is `@hotmail.co.uk`). Run `add-outlook` again with the
  right one.
- IMAP is switched off. In Outlook.com: **Settings → Mail → Forwarding and IMAP → Let
  devices and apps use IMAP**.

If Microsoft later says the sign-in has expired: `/usr/local/bin/mail-mcp auth hotmail`.

## Add a Gmail account

Turn on 2-Step Verification for the Google account, create an app password at
<https://myaccount.google.com/apppasswords>, then:

```sh
/usr/local/bin/mail-mcp add-gmail work you@gmail.com
```

The password is typed at a hidden prompt and stored in the keyring. An app password gives
full access to that mailbox; revoke it in your Google account if you stop using mail-mcp.

## Commands

```
mail-mcp                       run the MCP server (this is what the client starts)
mail-mcp list                  accounts and the settings in force
mail-mcp test [NAME]           check sign-in
mail-mcp log [N]               last N audit entries
mail-mcp set NAME KEY VALUE    display_name, signature, aliases, save_sent_copy
mail-mcp read-only on|off      switch every changing tool off or on
mail-mcp remove NAME           remove an account and its credentials
```

Changes apply the next time the client starts the server.

## Policy

`/etc/mail-mcp/policy.toml` (see [`policy.example.toml`](policy.example.toml)):

- `per_minute`, `per_day`: send limits per account.
- `attach_dirs`: the only folders files may be attached from.
- `read_only = true`: read-only mode that cannot be undone without root.
- `[[account]]` entries: pin the account list. With any listed, the server refuses to
  start if your config has an account that is not listed or whose address differs. Do
  this once your accounts are set up.

The server refuses to start if the policy file or its directory is not owned by root, is
writable by anyone else, is a symbolic link, or contains a setting it does not know.
There is no setting, anywhere, that turns approvals off.

## Recommended Claude Code deny rules

In `~/.claude/settings.json`, so the assistant is refused if it tries to touch mail-mcp's
files, run its commands or query the keyring from a shell:

```json
{
  "permissions": {
    "deny": [
      "Read(~/.config/mail-mcp/**)",
      "Edit(~/.config/mail-mcp/**)",
      "Read(~/.local/state/mail-mcp/**)",
      "Edit(~/.local/state/mail-mcp/**)",
      "Edit(//etc/mail-mcp/**)",
      "Edit(//usr/local/bin/mail-mcp)",
      "Edit(~/.local/bin/mail-mcp)",
      "Bash(mail-mcp *)",
      "Bash(/usr/local/bin/mail-mcp *)",
      "Bash(secret-tool *)",
      "Bash(kwallet-query *)",
      "Bash(kwalletcli *)",
      "Bash(keyring *)"
    ]
  }
}
```

## Where things are

| | |
|---|---|
| Binary | `/usr/local/bin/mail-mcp` (root-owned) |
| Policy | `/etc/mail-mcp/policy.toml` (root-owned) |
| Accounts | `~/.config/mail-mcp/config.toml` |
| Credentials | desktop keyring, service `mail-mcp` |
| Audit log | `~/.local/state/mail-mcp/audit.log`, and `journalctl -t mail-mcp` |
| Saved attachments | `~/Downloads/mail-attachments` |

## Development

```sh
cargo test                  # 120 offline tests
cargo test -- --ignored     # 4 live checks: keyring round trip, TLS to the mail servers,
                            # Microsoft's sign-in endpoint. No sign-in, nothing is sent.
cargo clippy --all-targets
```

The approval gate is tested end to end: a real MCP client and server talk over an
in-memory pipe, on both generations of the MCP protocol, and the tests assert that what is
sent is exactly what the dialog showed, that anything but a ticked box sends nothing, and
that an approval cannot be replayed or moved to a different message.

One module per concern:

| Module | Concern |
|---|---|
| `server.rs` | MCP tool definitions and the approval gate in front of them |
| `approval.rs` | Asking the user, on both generations of the MCP protocol |
| `ops.rs` | The mail operations behind each tool |
| `imap.rs`, `smtp.rs` | Talking to the mail servers; all command text is built from typed values |
| `compose.rs` | Building outgoing mail and the text of the approval dialog |
| `message.rs`, `html.rs`, `css.rs`, `sanitize.rs` | Turning received mail into safe, honest text |
| `attach.rs` | Files crossing between mailbox and disk |
| `config.rs` | User config, root-owned policy, validation |
| `oauth.rs`, `secrets.rs` | Microsoft sign-in and the keyring |
| `audit.rs` | Audit log and send limiter |
| `cli.rs` | The setup commands |

`legacy/python-original/` holds the first Python prototype, for reference only. It is not
built or used.

### Not yet done

- Sending, moving and Gmail have not been run against real mailboxes (see Status).
- The server has no way to unsubscribe from mailing lists, and it never follows links.
- Each tool call opens a new connection. Fine for normal use; slow for bulk work.
- Approval relies on the MCP client to show the dialog. A dialog the server shows itself
  would work in every host.
- A filesystem and network sandbox (Landlock) around the server process would limit the
  damage of a bug in one of the parsers.

## Licence

No licence has been chosen yet. Until one is added, the code is published for reading and
all rights are reserved.
