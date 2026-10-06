use crate::config::Config;
use crate::error::Error;
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info};

static PKCS11_INIT_ONCE: Once = Once::new();

pub struct HsmContext {
    pub pkcs11: Arc<Pkcs11>,
    pub slot: Slot,
    pub user_pin: String,
}

impl HsmContext {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let pkcs11 = Pkcs11::new(&config.pkcs11_lib_path)?;

        PKCS11_INIT_ONCE.call_once(|| {
            if let Err(e) = pkcs11.initialize(CInitializeArgs::OsThreads) {
                debug!("PKCS#11 initialize status: {e}");
            }
        });

        let pkcs11 = Arc::new(pkcs11);

        let slots = pkcs11.get_slots_with_token()?;
        if slots.is_empty() {
            return Err(Error::Pkcs11(
                "No slots with token present found".to_string(),
            ));
        }

        let slot = if let Some(target_slot) = config.slot_index {
            if (target_slot as usize) < slots.len() {
                slots[target_slot as usize]
            } else {
                return Err(Error::Pkcs11(format!(
                    "Slot index {target_slot} out of bounds (found {} slots)",
                    slots.len()
                )));
            }
        } else if let Some(ref target_label) = config.token_label {
            let mut found_slot = None;
            for s in slots {
                if let Ok(info) = pkcs11.get_token_info(s) {
                    if info.label().trim() == target_label.trim() {
                        found_slot = Some(s);
                        break;
                    }
                }
            }
            found_slot.ok_or_else(|| {
                Error::Pkcs11(format!("Token with label '{target_label}' not found"))
            })?
        } else {
            slots[0]
        };

        info!(slot = ?slot, "Initialized HSM context");

        Ok(Self {
            pkcs11,
            slot,
            user_pin: config.user_pin.clone(),
        })
    }
}

pub struct HsmSessionPool {
    ctx: Arc<HsmContext>,
    pool: Arc<Mutex<Vec<Session>>>,
    semaphore: Arc<Semaphore>,
    acquisition_timeout: Duration,
}

pub struct PooledSessionGuard {
    session: Option<Session>,
    pool: Arc<Mutex<Vec<Session>>>,
    _permit: OwnedSemaphorePermit,
}

impl PooledSessionGuard {
    pub fn session(&self) -> &Session {
        self.session.as_ref().expect("Session guard is valid")
    }
}

impl Drop for PooledSessionGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            if let Ok(mut guard) = self.pool.lock() {
                guard.push(session);
            }
        }
    }
}

impl HsmSessionPool {
    pub fn new(ctx: Arc<HsmContext>, max_sessions: usize, acquisition_timeout_ms: u64) -> Self {
        let pool = Arc::new(Mutex::new(Vec::with_capacity(max_sessions)));
        let semaphore = Arc::new(Semaphore::new(max_sessions));
        let acquisition_timeout = Duration::from_millis(acquisition_timeout_ms);

        Self {
            ctx,
            pool,
            semaphore,
            acquisition_timeout,
        }
    }

    pub async fn acquire(&self) -> Result<PooledSessionGuard, Error> {
        let permit = tokio::time::timeout(
            self.acquisition_timeout,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| Error::SessionPoolTimeout)?
        .map_err(|_| Error::SessionPoolClosed)?;

        {
            let mut lock = self.pool.lock().map_err(|_| Error::SessionPoolClosed)?;
            if let Some(session) = lock.pop() {
                debug!("Reusing existing HSM session from pool");
                return Ok(PooledSessionGuard {
                    session: Some(session),
                    pool: self.pool.clone(),
                    _permit: permit,
                });
            }
        }

        // Open a new session off Tokio async threads using spawn_blocking
        let ctx = self.ctx.clone();
        let session = tokio::task::spawn_blocking(move || -> Result<Session, Error> {
            debug!("Opening new HSM session");
            let session = ctx.pkcs11.open_rw_session(ctx.slot)?;

            if !ctx.user_pin.is_empty() {
                let pin = AuthPin::new(ctx.user_pin.clone());
                match session.login(UserType::User, Some(&pin)) {
                    Ok(_) => debug!("HSM user logged in successfully"),
                    Err(e) => {
                        let err_lower = e.to_string().to_lowercase();
                        if err_lower.contains("useralreadyloggedin")
                            || err_lower.contains("user_already_logged_in")
                            || err_lower.contains("already logged")
                        {
                            debug!("User already logged in on HSM slot");
                        } else {
                            return Err(Error::Pkcs11(format!("HSM login failed: {e}")));
                        }
                    }
                }
            }
            Ok(session)
        })
        .await
        .map_err(|e| Error::Pkcs11(format!("Blocking task failed: {e}")))??;

        Ok(PooledSessionGuard {
            session: Some(session),
            pool: self.pool.clone(),
            _permit: permit,
        })
    }
}
