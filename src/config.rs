use crate::error::Error;
use std::env;
use std::fmt;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Config {
    pub pkcs11_lib_path: PathBuf,
    pub token_label: Option<String>,
    pub slot_index: Option<u64>,
    pub user_pin: String,
    pub session_pool_size: usize,
    pub acquisition_timeout_ms: u64,
    pub hsm_operation_timeout_ms: u64,
    pub ecdsa_key_label: String,
    pub aes_key_label: String,
    pub bind_host: String,
    pub bind_port: u16,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("pkcs11_lib_path", &self.pkcs11_lib_path)
            .field("token_label", &self.token_label)
            .field("slot_index", &self.slot_index)
            .field("user_pin", &"[REDACTED]")
            .field("session_pool_size", &self.session_pool_size)
            .field("acquisition_timeout_ms", &self.acquisition_timeout_ms)
            .field("hsm_operation_timeout_ms", &self.hsm_operation_timeout_ms)
            .field("ecdsa_key_label", &self.ecdsa_key_label)
            .field("aes_key_label", &self.aes_key_label)
            .field("bind_host", &self.bind_host)
            .field("bind_port", &self.bind_port)
            .finish()
    }
}

impl Config {
    pub fn from_env() -> Result<Self, Error> {
        let _ = dotenvy::dotenv();

        let pkcs11_lib_path_str =
            env::var("PKCS11_LIB_PATH").unwrap_or_else(|_| Self::default_softhsm_lib_path());

        let pkcs11_lib_path = PathBuf::from(pkcs11_lib_path_str);

        let token_label = env::var("HSM_TOKEN_LABEL").ok();
        let slot_index = env::var("HSM_SLOT_INDEX")
            .ok()
            .and_then(|s| s.parse::<u64>().ok());

        let user_pin = env::var("HSM_USER_PIN").unwrap_or_default();

        let session_pool_size = env::var("HSM_SESSION_POOL_SIZE")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(4);

        let acquisition_timeout_ms = env::var("HSM_ACQUISITION_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5000);

        let hsm_operation_timeout_ms = env::var("HSM_OPERATION_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10000);

        let ecdsa_key_label = env::var("HSM_ECDSA_KEY_LABEL")
            .unwrap_or_else(|_| "arkion-intermediate-prod".to_string());

        let aes_key_label =
            env::var("HSM_AES_KEY_LABEL").unwrap_or_else(|_| "arkion-aes-key".to_string());

        let bind_host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let bind_port = env::var("PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(8080);

        Ok(Self {
            pkcs11_lib_path,
            token_label,
            slot_index,
            user_pin,
            session_pool_size,
            acquisition_timeout_ms,
            hsm_operation_timeout_ms,
            ecdsa_key_label,
            aes_key_label,
            bind_host,
            bind_port,
        })
    }

    fn default_softhsm_lib_path() -> String {
        if cfg!(target_os = "windows") {
            "C:\\Program Files\\SoftHSM2\\lib\\softhsm2-x64.dll".to_string()
        } else if cfg!(target_os = "macos") {
            "/usr/local/lib/softhsm/libsofthsm2.so".to_string()
        } else {
            "/usr/lib/softhsm/libsofthsm2.so".to_string()
        }
    }
}
