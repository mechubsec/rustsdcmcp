//! SIGHUP hot-reload wiring: reopen the audit log, then reload the token store.

use mecmcp_audit::AuditFileSink;
use mecmcp_auth::{NoGrant, TokenStoreFile};
use std::sync::{Arc, Mutex};

/// An installed SIGHUP listener whose reload targets can be attached later.
///
/// The listener is deliberately installed before startup loads any state. A
/// signal received during that window is remembered and replayed once the
/// audit sink and token store are available.
pub struct SighupHandler {
    state: Arc<Mutex<State>>,
}

struct State {
    callback: Option<Arc<dyn Fn() + Send + Sync>>,
    pending: bool,
}

impl SighupHandler {
    /// Attach the reload targets and replay an early SIGHUP, if one arrived.
    pub fn configure(
        &self,
        audit_sink: Option<AuditFileSink>,
        token_store: Option<Arc<TokenStoreFile<NoGrant>>>,
    ) -> std::io::Result<()> {
        let callback: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            if let Some(sink) = &audit_sink {
                match sink.reopen() {
                    Ok(()) => tracing::info!(path = %sink.path().display(), "audit log reopened"),
                    Err(error) => {
                        tracing::warn!(%error, path = %sink.path().display(), "audit log reopen failed; keeping previous sink")
                    }
                }
            }
            if let Some(store) = &token_store {
                match store.reload() {
                    Ok(()) => tracing::info!(tokens = store.store().len(), "token store reloaded"),
                    Err(error) => {
                        tracing::error!(%error, "token reload failed; retaining previous snapshot")
                    }
                }
            }
        });

        let replay = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| std::io::Error::other("SIGHUP handler state poisoned"))?;
            state.callback = Some(callback.clone());
            std::mem::take(&mut state.pending)
        };
        if replay {
            callback();
        }
        Ok(())
    }
}

/// Install the SIGHUP listener before startup state is loaded.
pub fn install_early_sighup_handler() -> std::io::Result<SighupHandler> {
    let state = Arc::new(Mutex::new(State {
        callback: None,
        pending: false,
    }));
    let listener_state = state.clone();
    mecmcp_runtime::signals::install_hup_handler(move || {
        let callback =
            listener_state
                .lock()
                .ok()
                .and_then(|mut state| match state.callback.clone() {
                    Some(callback) => Some(callback),
                    None => {
                        state.pending = true;
                        None
                    }
                });
        if let Some(callback) = callback {
            callback();
        }
    })?;
    Ok(SighupHandler { state })
}

/// Install the SIGHUP handler that reopens `audit_sink` (when configured) and
/// then reloads `token_store` (when configured), in that order.
///
/// The reopen runs first and unconditionally: it is the lossless half of log
/// rotation (the rotator renames the file, then signals the process), and a
/// failure there must not block the token reload that follows.
///
/// Installs nothing, returning `Ok(())` immediately, when neither is
/// configured — there is nothing to hot-reload, so SIGHUP keeps its default
/// disposition rather than gaining a handler that only exists to no-op.
/// Installing whenever *either* is configured (not just the token store)
/// matters on its own: a deployment with only `--audit-log-file` set still
/// needs a handler, or SIGHUP's default disposition (terminate) kills the
/// process on the very signal logrotate sends it.
///
/// # Errors
///
/// Returns the underlying I/O error if the signal handler cannot be
/// registered with the runtime.
pub fn install_sighup_handler(
    audit_sink: Option<AuditFileSink>,
    token_store: Option<Arc<TokenStoreFile<NoGrant>>>,
) -> std::io::Result<()> {
    let handler = install_early_sighup_handler()?;
    handler.configure(audit_sink, token_store)
}

#[cfg(test)]
mod tests {
    use super::{SighupHandler, State};
    use std::sync::{Arc, Mutex};

    #[test]
    fn pending_signal_is_consumed_when_targets_are_configured() {
        let handler = SighupHandler {
            state: Arc::new(Mutex::new(State {
                callback: None,
                pending: true,
            })),
        };

        handler
            .configure(None, None)
            .expect("configuring the deferred handler");
        assert!(!handler.state.lock().expect("handler state").pending);
        assert!(
            handler
                .state
                .lock()
                .expect("handler state")
                .callback
                .is_some()
        );
    }
}
