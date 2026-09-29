use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use time::{Duration, OffsetDateTime};

/// Apple clients reject leaf certificates valid for longer than 398 days.
const VALIDITY_DAYS: i64 = 397;

/// Per-run interception state. The CA key is generated when `hush run` starts
/// and only ever lives in its memory — it is never written to disk, so the CA
/// stops being usable the moment the run exits.
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

        let (cert, key_der) = self.issue_leaf(host)?;
        let chain = vec![cert, self.ca.der().clone()];
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key_der)?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];

        let cfg = Arc::new(cfg);
        leaves.insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

impl Mitm {
    fn issue_leaf(&self, host: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let mut params = CertificateParams::new(vec![host.to_string()])?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // Required by OpenSSL's strict verification, the default since Python 3.13.
        params.use_authority_key_identifier_extension = true;
        set_validity(&mut params);
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.ca)?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Ok((cert.der().clone(), key_der))
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

pub struct TrustFiles {
    /// The session CA alone, for `NODE_EXTRA_CA_CERTS` (which appends).
    pub ca: PathBuf,
    /// System roots plus the session CA, for `SSL_CERT_FILE` and friends
    /// (which replace the default roots entirely).
    pub bundle: PathBuf,
}

/// Writes the CA files a child process is pointed at into `dir`. Both
/// contain only public certificates.
pub fn write_trust_files(mitm: &Mitm, system_roots: &[CertificateDer<'static>], dir: &Path) -> Result<TrustFiles> {
    let ca_pem = to_pem(mitm.ca_der());
    let mut bundle_pem: String = system_roots.iter().map(to_pem).collect();
    bundle_pem.push_str(&ca_pem);

    let files = TrustFiles { ca: dir.join("ca.pem"), bundle: dir.join("ca-bundle.pem") };
    fs::write(&files.ca, ca_pem).with_context(|| format!("writing {}", files.ca.display()))?;
    fs::write(&files.bundle, bundle_pem).with_context(|| format!("writing {}", files.bundle.display()))?;
    Ok(files)
}

fn to_pem(der: &CertificateDer<'_>) -> String {
    pem::encode(&pem::Pem::new("CERTIFICATE", der.to_vec()))
}

#[cfg(test)]
mod tests {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::parse_x509_certificate;

    use super::*;

    fn mitm() -> Mitm {
        Mitm::new(RootCertStore::empty()).unwrap()
    }

    #[test]
    fn session_ca_is_a_ca_limited_to_leaves() {
        let m = mitm();
        let (_, ca) = parse_x509_certificate(m.ca_der()).unwrap();
        let bc = ca.basic_constraints().unwrap().expect("basic constraints").value;
        assert!(bc.ca);
        assert_eq!(bc.path_len_constraint, Some(0));
        assert!(ca.key_usage().unwrap().expect("key usage").value.key_cert_sign());
    }

    /// Guards the fields strict clients check: a missing AKI broke Python 3.13+,
    /// and Apple rejects leaves valid for more than 398 days.
    #[test]
    fn leaf_meets_strict_client_requirements() {
        let m = mitm();
        let (der, _) = m.issue_leaf("api.example.com").unwrap();
        let (_, leaf) = parse_x509_certificate(&der).unwrap();
        let (_, ca) = parse_x509_certificate(m.ca_der()).unwrap();

        assert_eq!(leaf.issuer(), ca.subject());
        assert!(!leaf.is_ca());
        assert!(
            leaf.extensions()
                .iter()
                .any(|e| matches!(e.parsed_extension(), ParsedExtension::AuthorityKeyIdentifier(_))),
            "leaf must carry an Authority Key Identifier"
        );
        assert!(leaf.extended_key_usage().unwrap().expect("EKU").value.server_auth);
        let san = leaf.subject_alternative_name().unwrap().expect("SAN").value;
        assert_eq!(san.general_names, vec![GeneralName::DNSName("api.example.com")]);

        let v = leaf.validity();
        let days = (v.not_after.timestamp() - v.not_before.timestamp()) / 86_400;
        assert!(days <= 398, "leaf valid for {days} days");
        assert!(v.is_valid(), "leaf must be valid now");
    }

    #[test]
    fn leaf_configs_are_cached_per_host() {
        let m = mitm();
        let a = m.server_config("a.example.com").unwrap();
        assert!(Arc::ptr_eq(&a, &m.server_config("a.example.com").unwrap()));
        assert!(!Arc::ptr_eq(&a, &m.server_config("b.example.com").unwrap()));
    }

    #[test]
    fn each_session_gets_a_fresh_ca() {
        assert_ne!(mitm().ca_der(), mitm().ca_der());
    }
}
