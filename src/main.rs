use clap::Parser;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt::Write;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

/// vault-cp is a way to recursively copy secrets from one vault path to another
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Vault destination path to copy secrets to
    #[arg(short, long, default_value = "")]
    dst_path: String,

    /// Vault source path to copy secrets from, string must end with a '/'
    #[arg(short, long, default_value = "")]
    src_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct TestSecret {
    user: String,
    password: String,
}

#[tokio::main]
async fn main() {
    // Check environment variables for vault configs
    let vault_addr = match env::var_os("VAULT_ADDR") {
        Some(v) => v.into_string().unwrap(),
        None => "http://127.0.0.1:8200".to_string(),
    };

    let vault_token = env::var("VAULT_TOKEN").expect("$VAULT_TOKEN is not set");

    let args = Args::parse();

    if args.dst_path == "" || args.src_path == "" {
        panic!("need to set --src_path and --dst_path arguments")
    }

    println!("$VAULT_ADDR: {}", vault_addr);
    println!("$VAULT_TOKEN: {}", vault_token);
    println!("src-path: {}", args.src_path);
    println!("dst-path: {}", args.dst_path);

    let vault_client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(vault_addr)
            .token(vault_token)
            .build()
            .unwrap(),
    )
    .unwrap();

    let list_secrets = list_vault_secrets(&vault_client, &args.src_path).await;

    if let Ok(secrets) = list_secrets {
        for s in secrets {
            // read secret
            let mut src_path = args.src_path.to_string();
            let mut dst_path = args.dst_path.to_string();
            write!(src_path, "{}", s).unwrap();
            write!(dst_path, "{}", s).unwrap();
            let src_secret = get_vault_secret(&vault_client, &src_path).await;

            // copy over secrets to destination
            if let Ok(src_s) = src_secret {
                let dst_secret = TestSecret {
                    user: src_s.user,
                    password: src_s.password,
                };
                println!(
                    "copying secret: {:?}, from path: {}, to path: {}",
                    dst_secret, src_path, dst_path
                );
                let _ = kv2::set(&vault_client, "secret", &dst_path, &dst_secret).await;
            }
        }
    } else if let Err(e) = list_secrets {
        eprintln!("{}", e)
    }
}

async fn list_vault_secrets(client: &VaultClient, src: &String) -> Result<Vec<String>, String> {
    return match kv2::list(client, "secret", src).await {
        Ok(v) => Ok(v),
        Err(e) => return Err(e.to_string()),
    };
}

async fn get_vault_secret(client: &VaultClient, src: &String) -> Result<TestSecret, String> {
    return match kv2::read(client, "secret", src).await {
        Ok(v) => Ok(v),
        Err(e) => return Err(e.to_string()),
    };
}
