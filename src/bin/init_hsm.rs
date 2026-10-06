use arkion_rust_hsm_signing_service::hsm::{generate_aes_256_key, generate_ecdsa_p256_keypair};
use arkion_rust_hsm_signing_service::{Config, HsmContext};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== SoftHSM Token Key Provisioning Utility ===");
    let config = Config::from_env()?;

    println!(
        "Attempting to connect to PKCS#11 library at: {:?}",
        config.pkcs11_lib_path
    );
    let ctx = match HsmContext::new(&config) {
        Ok(ctx) => Arc::new(ctx),
        Err(e) => {
            println!("Could not connect to SoftHSM library: {e}");
            println!(
                "Skipping automated key provisioning. SoftHSM library must be installed first."
            );
            return Ok(());
        }
    };

    let session = ctx.pkcs11.open_rw_session(ctx.slot)?;
    if !config.user_pin.is_empty() {
        let pin = cryptoki::types::AuthPin::new(config.user_pin.clone());
        let _ = session.login(cryptoki::session::UserType::User, Some(&pin));
    }

    println!(
        "Provisioning ECDSA P-256 keypair ('{}')...",
        config.ecdsa_key_label
    );
    generate_ecdsa_p256_keypair(&session, &config.ecdsa_key_label)?;
    println!("ECDSA P-256 keypair successfully provisioned.");

    println!("Provisioning AES-256 key ('{}')...", config.aes_key_label);
    generate_aes_256_key(&session, &config.aes_key_label)?;
    println!("AES-256 key successfully provisioned.");

    println!("All keys provisioned in SoftHSM successfully!");
    Ok(())
}
