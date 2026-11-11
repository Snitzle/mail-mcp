//! Process-level hardening applied before anything else runs.

use rustix::process::{DumpableBehavior, Resource, Rlimit, set_dumpable_behavior, setrlimit};

/// Keep secrets held in memory away from other processes and from disk:
/// no core dumps, no ptrace or `/proc/<pid>/mem` access by other processes of the same
/// user, and no gaining privileges through setuid binaries.
///
/// Each step is best effort: failing to harden must not stop mail from working.
pub fn harden_process() {
    let _ = setrlimit(
        Resource::Core,
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    );
    let _ = set_dumpable_behavior(DumpableBehavior::NotDumpable);
    let _ = rustix::thread::set_no_new_privs(true);
}
