use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    AddSecret {
        name: String,
        value: String,
        host: String,
        env: Option<String>,
        header: Option<String>,
        format: Option<String>,
    },
    BindSecret {
        name: String,
        host: String,
        env: Option<String>,
        header: Option<String>,
        format: Option<String>,
    },
    RemoveSecret {
        name: String,
    },
    ListSecrets,
    Mint {
        names: Vec<String>,
        env: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BindingInfo {
    pub host: String,
    pub env: Option<String>,
    pub header: String,
    pub format: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretInfo {
    pub name: String,
    pub bindings: Vec<BindingInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Error {
        message: String,
    },
    SecretList {
        secrets: Vec<SecretInfo>,
    },
    Minted {
        proxy_port: u16,
        placeholders: std::collections::HashMap<String, String>,
        unmatched: Vec<String>,
    },
}
