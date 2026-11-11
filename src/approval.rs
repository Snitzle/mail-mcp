//! Asking the user before anything irreversible happens.
//!
//! Sending mail, copying mail to another account, moving mail to trash or spam, and
//! uploading local files into a draft all stop here first. The user is shown exactly what
//! is about to happen and must tick a box to allow it. If the question cannot be put to
//! the user, or the answer is anything other than a clear yes, nothing is done.
//!
//! There are two ways the question reaches the user, depending on the protocol version the
//! client speaks:
//!
//! * **Before 2026-07-28** the server sends an elicitation request in the middle of the
//!   tool call and waits for the answer.
//! * **From 2026-07-28** the server ends the call with "input required"; the client asks
//!   the user and calls the tool again with the answer. Between the two calls the prepared
//!   action is kept here, in memory, under a random single-use handle. The second call
//!   executes exactly what was shown: nothing is recomputed from the arguments, so the
//!   action cannot change between the dialog and its execution.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rmcp::model::{
    ElicitRequest, ElicitRequestParams, ElicitationSchema, InputRequest, InputRequests,
    InputRequiredResult, InputResponses, ProtocolVersion,
};
use rmcp::schemars::{self, JsonSchema};
use rmcp::service::{ElicitationError, RequestContext, RoleServer};
use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};

const RESPONSE_KEY: &str = "approval";
/// How long a prepared action waits for the user's answer.
const PENDING_LIFETIME: Duration = Duration::from_secs(15 * 60);
const MAX_PENDING: usize = 16;

const REFUSED: &str =
    "The user did not approve this, so nothing was done. Do not try again unless the user asks.";
const CANNOT_ASK: &str = "The user could not be asked to approve this, so nothing was done. Approval dialogs need an interactive Claude Code session.";

/// The form shown under the description: a single checkbox.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct Approve {
    /// Tick to approve. Leave unticked to refuse.
    pub approve: bool,
}

rmcp::elicit_safe!(Approve);

struct Pending {
    tool: &'static str,
    /// The tool call's arguments, as JSON text. The retry must carry the same ones.
    arguments: String,
    created: Instant,
    payload: Box<dyn Any + Send>,
}

/// What a gated tool should do next.
pub enum Gate<T> {
    /// Approved: carry out the action.
    Proceed(T),
    /// Hand this back to the client; it will ask the user and call the tool again.
    Ask(Box<InputRequiredResult>),
}

#[derive(Default)]
pub struct Approvals {
    pending: Mutex<HashMap<String, Pending>>,
}

impl Approvals {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Keep a prepared action until the user answers. Returns its handle.
    fn store<T: Send + 'static>(
        &self,
        tool: &'static str,
        arguments: &str,
        payload: T,
    ) -> Result<String> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| Error::denied(format!("no randomness available: {e}")))?;
        let handle: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

        let mut pending = self.lock();
        pending.retain(|_, p| p.created.elapsed() < PENDING_LIFETIME);
        while pending.len() >= MAX_PENDING {
            // Drop the oldest; its dialog, if still open, will simply fail closed.
            let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, p)| p.created)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            pending.remove(&oldest);
        }
        pending.insert(
            handle.clone(),
            Pending {
                tool,
                arguments: arguments.to_owned(),
                created: Instant::now(),
                payload: Box::new(payload),
            },
        );
        Ok(handle)
    }

    /// Take back a prepared action for the second call. A handle works once, only for the
    /// same tool with the same arguments, and only for a limited time.
    fn take<T: 'static>(&self, tool: &str, arguments: &str, handle: &str) -> Result<T> {
        let expired = || {
            Error::denied(
                "That approval request has expired or was already used. Start the action again.",
            )
        };
        // Removed before any check, so a handle can never be presented twice.
        let pending = self.lock().remove(handle).ok_or_else(expired)?;
        if pending.created.elapsed() >= PENDING_LIFETIME
            || pending.tool != tool
            || pending.arguments != arguments
        {
            return Err(expired());
        }
        pending
            .payload
            .downcast::<T>()
            .map(|payload| *payload)
            .map_err(|_| expired())
    }

    /// Second call of the two-call flow: check the user's answer and release the action.
    pub fn resume<T: 'static>(
        &self,
        tool: &str,
        arguments: &str,
        handle: &str,
        responses: Option<&InputResponses>,
    ) -> Result<T> {
        // Take first: whatever the answer was, the handle is now spent.
        let payload = self.take::<T>(tool, arguments, handle)?;
        let answer = responses
            .and_then(|r| r.get(RESPONSE_KEY))
            .ok_or_else(|| Error::denied(REFUSED))?;
        if is_approval(answer) {
            Ok(payload)
        } else {
            Err(Error::denied(REFUSED))
        }
    }

    /// First call: put the question to the user in whichever way the client supports.
    pub async fn ask<T: Send + 'static>(
        &self,
        context: &RequestContext<RoleServer>,
        tool: &'static str,
        arguments: &str,
        description: String,
        payload: T,
    ) -> Result<Gate<T>> {
        let can_elicit = context
            .client_capabilities()
            .is_some_and(|c| c.elicitation.is_some());
        if !can_elicit {
            return Err(Error::denied(CANNOT_ASK));
        }
        let two_call = context
            .protocol_version()
            .is_some_and(|v| v >= ProtocolVersion::V_2026_07_28);
        if two_call {
            let schema = ElicitationSchema::from_type::<Approve>()
                .map_err(|e| Error::denied(format!("{CANNOT_ASK} ({e})")))?;
            let request = ElicitRequest::new(ElicitRequestParams::FormElicitationParams {
                meta: None,
                message: description,
                requested_schema: schema,
            });
            let handle = self.store(tool, arguments, payload)?;
            let mut requests = InputRequests::new();
            requests.insert(RESPONSE_KEY.to_owned(), InputRequest::Elicitation(request));
            return Ok(Gate::Ask(Box::new(InputRequiredResult::new(
                Some(requests),
                Some(handle),
            ))));
        }
        match context.peer.elicit::<Approve>(description).await {
            Ok(Some(Approve { approve: true })) => Ok(Gate::Proceed(payload)),
            Ok(_)
            | Err(
                ElicitationError::UserDeclined
                | ElicitationError::UserCancelled
                | ElicitationError::NoContent,
            ) => Err(Error::denied(REFUSED)),
            Err(e) => Err(Error::denied(format!("{CANNOT_ASK} ({e})"))),
        }
    }
}

/// Is this elicitation result an explicit approval? Anything else, including an accepted
/// form with the box left unticked, is a refusal.
fn is_approval(answer: &Value) -> bool {
    answer.get("action").and_then(Value::as_str) == Some("accept")
        && answer
            .get("content")
            .and_then(|c| c.get("approve"))
            .and_then(Value::as_bool)
            == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn responses(answer: Value) -> InputResponses {
        let mut map = InputResponses::new();
        map.insert(RESPONSE_KEY.to_owned(), answer);
        map
    }

    fn approved() -> InputResponses {
        responses(json!({ "action": "accept", "content": { "approve": true } }))
    }

    #[test]
    fn only_an_explicit_yes_counts() {
        assert!(is_approval(
            &json!({ "action": "accept", "content": { "approve": true } })
        ));
        for no in [
            json!({ "action": "accept", "content": { "approve": false } }),
            json!({ "action": "accept", "content": {} }),
            json!({ "action": "accept" }),
            json!({ "action": "accept", "content": { "approve": "true" } }),
            json!({ "action": "accept", "content": { "approve": 1 } }),
            json!({ "action": "decline", "content": { "approve": true } }),
            json!({ "action": "cancel" }),
            json!({ "content": { "approve": true } }),
            json!(null),
            json!("accept"),
        ] {
            assert!(!is_approval(&no), "{no}");
        }
    }

    #[test]
    fn approved_action_is_released_once() {
        let approvals = Approvals::default();
        let handle = approvals
            .store("send_email", "{\"to\":\"a\"}", String::from("the message"))
            .expect("store");
        let payload: String = approvals
            .resume("send_email", "{\"to\":\"a\"}", &handle, Some(&approved()))
            .expect("resume");
        assert_eq!(payload, "the message");
        // The same handle cannot be used again.
        assert!(
            approvals
                .resume::<String>("send_email", "{\"to\":\"a\"}", &handle, Some(&approved()))
                .is_err()
        );
    }

    #[test]
    fn refusal_spends_the_handle() {
        let approvals = Approvals::default();
        let handle = approvals.store("send_email", "{}", 1u32).expect("store");
        let declined = responses(json!({ "action": "decline" }));
        assert!(
            approvals
                .resume::<u32>("send_email", "{}", &handle, Some(&declined))
                .is_err()
        );
        // Saying yes afterwards does not revive it.
        assert!(
            approvals
                .resume::<u32>("send_email", "{}", &handle, Some(&approved()))
                .is_err()
        );
    }

    #[test]
    fn missing_answer_is_a_refusal() {
        let approvals = Approvals::default();
        let handle = approvals.store("send_email", "{}", 1u32).expect("store");
        assert!(
            approvals
                .resume::<u32>("send_email", "{}", &handle, None)
                .is_err()
        );
        let handle = approvals.store("send_email", "{}", 1u32).expect("store");
        assert!(
            approvals
                .resume::<u32>("send_email", "{}", &handle, Some(&InputResponses::new()))
                .is_err()
        );
    }

    #[test]
    fn handle_is_bound_to_tool_and_arguments() {
        let approvals = Approvals::default();
        let handle = approvals
            .store("move_email", "{\"uids\":[1]}", 1u32)
            .expect("store");
        assert!(
            approvals
                .resume::<u32>("send_email", "{\"uids\":[1]}", &handle, Some(&approved()))
                .is_err()
        );
        let handle = approvals
            .store("move_email", "{\"uids\":[1]}", 1u32)
            .expect("store");
        assert!(
            approvals
                .resume::<u32>("move_email", "{\"uids\":[1,2]}", &handle, Some(&approved()))
                .is_err()
        );
    }

    #[test]
    fn unknown_and_guessed_handles_fail() {
        let approvals = Approvals::default();
        assert!(
            approvals
                .resume::<u32>("send_email", "{}", "", Some(&approved()))
                .is_err()
        );
        assert!(
            approvals
                .resume::<u32>("send_email", "{}", &"0".repeat(64), Some(&approved()))
                .is_err()
        );
    }

    #[test]
    fn handles_are_long_and_unique() {
        let approvals = Approvals::default();
        let a = approvals.store("t", "{}", ()).expect("store");
        let b = approvals.store("t", "{}", ()).expect("store");
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn pending_actions_are_bounded() {
        let approvals = Approvals::default();
        let first = approvals.store("t", "{}", 0usize).expect("store");
        for i in 1..=MAX_PENDING {
            approvals.store("t", "{}", i).expect("store");
        }
        assert_eq!(approvals.lock().len(), MAX_PENDING);
        assert!(
            approvals
                .resume::<usize>("t", "{}", &first, Some(&approved()))
                .is_err()
        );
    }

    #[test]
    fn wrong_payload_type_fails_closed() {
        let approvals = Approvals::default();
        let handle = approvals.store("t", "{}", 1u32).expect("store");
        assert!(
            approvals
                .resume::<String>("t", "{}", &handle, Some(&approved()))
                .is_err()
        );
    }
}
