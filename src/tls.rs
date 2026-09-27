use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use time::{Duration, OffsetDateTime};

use crate::vault::{ca_bundle_path, ca_cert_path};

/// Apple clients reject leaf certificates valid for longer than 398 days.
const VALIDITY_DAYS: i64 = 397;

/// Per-session interception state. The CA key is generated at `hush unlock`
/// and only ever lives in this process's memory — it is never written to disk,
/// so the CA stops being usable the moment the agent exits.
pub struct Mitm {
    ca: CertifiedIssuer<'static, KeyPair>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
    upstream: Arc<ClientConfig>,
}

impl Mitm {
    /// `upstream_roots` are the roots used to verify the real servers hush
    /// connects to on the child's behalf.
    pub fn new(upstream_roots: RootCertStore) -> Result<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name.push(DnType::CommonName, "hush session CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        set_validity(&mut params);
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate()?)?;

        let mut upstream = ClientConfig::builder()
            .with_root_certificates(upstream_roots)
            .with_no_client_auth();
        upstream.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Mitm {
            ca,
            leaves: Mutex::new(HashMap::new()),
            upstream: Arc::new(upstream),
        })
    }

    pub fn ca_der(&self) -> &CertificateDer<'static> {
        self.ca.der()
    }

    pub fn upstream_config(&self) -> Arc<ClientConfig> {
        self.upstream.clone()
    }

    /// Server config presenting a certificate for `host`, signed by the session CA.
    /// Generated on first use and cached for the agent's lifetime.
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let mut leaves = self.leaves.lock().unwrap();
        if let Some(cfg) = leaves.get(host) {
            return Ok(cfg.clone());
        }

        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // Required by OpenSSL's strict verification, the default since Python 3.13.
        params.use_authority_key_identifier_extension = true;
        set_validity(&mut params);
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.ca)?;

        let chain = vec![cert.der().clone(), self.ca.der().clone()];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key_der)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        let cfg = Arc::new(cfg);
        leaves.insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

fn set_validity(params: &mut CertificateParams) {
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(VALIDITY_DAYS);
}

/// Loads the OS trust store: as a `RootCertStore` for verifying upstreams, and
/// as raw certificates for the bundle handed to child processes.
pub fn native_roots() -> Result<(RootCertStore, Vec<CertificateDer<'static>>)> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut store = RootCertStore::empty();
    let (added, _) = store.add_parsable_certificates(loaded.certs.iter().cloned());
    if added == 0 {
        anyhow::bail!("no usable root certificates found in the system trust store");
    }
    Ok((store, loaded.certs))
}

/// Writes the files `hush run` points child processes at:
/// - `ca.pem`: the session CA alone (for `NODE_EXTRA_CA_CERTS`, which appends)
/// - `ca-bundle.pem`: system roots plus the session CA (for `SSL_CERT_FILE` and
///   friends, which replace the default roots entirely)
///
/// Both contain only public certificates.
pub fn write_trust_files(mitm: &Mitm, system_roots: &[CertificateDer<'static>]) -> Result<()> {
    let ca_pem = to_pem(mitm.ca_der());
    let mut bundle: String = system_roots.iter().map(to_pem).collect();
    bundle.push_str(&ca_pem);

    write_atomic(&ca_cert_path()?, &ca_pem)?;
    write_atomic(&ca_bundle_path()?, &bundle)?;
    Ok(())
}

fn to_pem(der: &CertificateDer<'_>) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", der.to_vec()))
}

fn write_atomic(path: &std::path::Path, contents: &str) -> Result<()> {
    let tmp = path.with_extension("pem.tmp");
    fs::write(&tmp, contents).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path)?;
    Ok(())
}
