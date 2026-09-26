use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::Result;
use rand::RngCore;

use crate::protocol::{BindingInfo, Request, Response, SecretInfo};
use crate::proxy::{start_proxy, PlaceholderEntry, PlaceholderTable};
use crate::vault::{save_vault, socket_path, Binding, SecretEntry, Vault};

struct AgentState {
    vault: Mutex<Vault>,
    passphrase: String,
    placeholders: PlaceholderTable,
    proxy_port: u16,
}

pub fn run(vault: Vault, passphrase: String) -> Result<()> {
    let path = socket_path()?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    let placeholders: PlaceholderTable = Arc::new(Mutex::new(HashMap::new()));
    let proxy_port = start_proxy(placeholders.clone())?;

    let state = Arc::new(AgentState {
        vault: Mutex::new(vault),
        passphrase,
        placeholders,
        proxy_port,
    });

    let listener = UnixListener::bind(&path)?;
    set_owner_only(&path)?;

    eprintln!("hush-agent listening on {} (proxy on 127.0.0.1:{})", path.display(), proxy_port);
    eprintln!("leave this running for the session; `hush run` talks to it automatically.");

    for stream in listener.incoming() {
        match stream {
            Ok(conn) => {
                let state = state.clone();
                thread::spawn(move || {
                    let _ = handle_client(conn, state);
                });
            }
            Err(_) => continue,
        }
    }

    Ok(())
}

fn handle_client(stream: UnixStream, state: Arc<AgentState>) -> Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Ok(());
    }

    let req: Request = serde_json::from_str(line.trim())?;
    let resp = handle_request(req, &state);
    let out = serde_json::to_string(&resp)?;
    writer.write_all(out.as_bytes())?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn handle_request(req: Request, state: &Arc<AgentState>) -> Response {
    match req {
        Request::Ping => Response::Ok,

        Request::AddSecret { name, value, host, env, header, format } => {
            let mut vault = state.vault.lock().unwrap();
            let binding = Binding {
                host,
                env,
                header: header.unwrap_or_else(|| "Authorization".to_string()),
                format: format.unwrap_or_else(|| "Bearer {value}".to_string()),
            };
            vault.secrets.insert(name, SecretEntry { value, bindings: vec![binding] });
            match save_vault(&vault, &state.passphrase) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error { message: e.to_string() },
            }
        }

        Request::BindSecret { name, host, env, header, format } => {
            let mut vault = state.vault.lock().unwrap();
            match vault.secrets.get_mut(&name) {
                Some(entry) => {
                    entry.bindings.push(Binding {
                        host,
                        env,
                        header: header.unwrap_or_else(|| "Authorization".to_string()),
                        format: format.unwrap_or_else(|| "Bearer {value}".to_string()),
                    });
                    match save_vault(&vault, &state.passphrase) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Error { message: e.to_string() },
                    }
                }
                None => Response::Error { message: format!("no such secret: {name}") },
            }
        }

        Request::RemoveSecret { name } => {
            let mut vault = state.vault.lock().unwrap();
            if vault.secrets.remove(&name).is_some() {
                match save_vault(&vault, &state.passphrase) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Error { message: e.to_string() },
                }
            } else {
                Response::Error { message: format!("no such secret: {name}") }
            }
        }

        Request::ListSecrets => {
            let vault = state.vault.lock().unwrap();
            let secrets = vault
                .secrets
                .iter()
                .map(|(name, entry)| SecretInfo {
                    name: name.clone(),
                    bindings: entry
                        .bindings
                        .iter()
                        .map(|b| BindingInfo {
                            host: b.host.clone(),
                            env: b.env.clone(),
                            header: b.header.clone(),
                            format: b.format.clone(),
                        })
                        .collect(),
                })
                .collect();
            Response::SecretList { secrets }
        }

        Request::Mint { names, env } => {
            let vault = state.vault.lock().unwrap();
            let mut placeholders_out = HashMap::new();
            let mut unmatched = Vec::new();
            let mut table = state.placeholders.lock().unwrap();

            for name in names {
                match vault.find_binding(&name, env.as_deref()) {
                    Some((entry, binding)) => {
                        let placeholder = generate_placeholder();
                        table.insert(
                            placeholder.clone(),
                            PlaceholderEntry {
                                real_value: entry.value.clone(),
                                host: binding.host.clone(),
                                header: binding.header.clone(),
                                format: binding.format.clone(),
                            },
                        );
                        placeholders_out.insert(name, placeholder);
                    }
                    None => unmatched.push(name),
                }
            }

            Response::Minted {
                proxy_port: state.proxy_port,
                placeholders: placeholders_out,
                unmatched,
            }
        }
    }
}

fn generate_placeholder() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("hush_ph_{hex}")
}

#[cfg(unix)]
fn set_owner_only(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
