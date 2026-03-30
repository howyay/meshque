use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ring::digest;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};

pub struct NodeIdentity {
    pub peer_id: String,
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub fingerprint: String,
}

impl NodeIdentity {
    pub fn certificate(&self) -> CertificateDer<'static> {
        CertificateDer::from(self.certificate_der.clone())
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivatePkcs8KeyDer::from(self.private_key_der.clone()).into()
    }
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    version: u8,
    peer_id: String,
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    issuer: String,
    created_at_millis: u64,
}

pub fn load_or_create_identity(identity_file: Option<&Path>) -> Result<NodeIdentity> {
    let path = resolve_identity_path(identity_file)?;
    if path.exists() {
        load_identity(&path)
    } else {
        create_identity(&path)
    }
}

fn load_identity(path: &Path) -> Result<NodeIdentity> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read identity file '{}'", path.display()))?;
    let stored: StoredIdentity = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse identity file '{}'", path.display()))?;

    Ok(NodeIdentity {
        peer_id: stored.peer_id,
        fingerprint: cert_fingerprint(&stored.certificate_der),
        certificate_der: stored.certificate_der,
        private_key_der: stored.private_key_der,
    })
}

fn create_identity(path: &Path) -> Result<NodeIdentity> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create identity dir '{}'", parent.display()))?;
        set_owner_only_permissions(parent, 0o700)?;
    }

    let cert = rcgen::generate_simple_self_signed(vec!["meshque-peer".into()])?;
    let certificate_der = cert.cert.der().to_vec();
    let private_key_der = cert.key_pair.serialize_der();
    let peer_id = uuid_simple();

    let stored = StoredIdentity {
        version: 1,
        peer_id: peer_id.clone(),
        certificate_der: certificate_der.clone(),
        private_key_der: private_key_der.clone(),
        issuer: "self".to_string(),
        created_at_millis: now_millis(),
    };

    let temp_path = path.with_extension("tmp");
    let body = serde_json::to_vec_pretty(&stored)?;
    fs::write(&temp_path, body)
        .with_context(|| format!("failed to write identity file '{}'", temp_path.display()))?;
    set_owner_only_permissions(&temp_path, 0o600)?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to move identity file '{}' into place at '{}'",
            temp_path.display(),
            path.display()
        )
    })?;

    Ok(NodeIdentity {
        peer_id,
        fingerprint: cert_fingerprint(&certificate_der),
        certificate_der,
        private_key_der,
    })
}

fn resolve_identity_path(identity_file: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = identity_file {
        return Ok(path.to_path_buf());
    }

    if let Some(config_dir) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(config_dir)
            .join("meshque")
            .join("identity.json"));
    }

    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home)
            .join(".config")
            .join("meshque")
            .join("identity.json"));
    }

    anyhow::bail!(
        "failed to resolve identity file path: set HOME, XDG_CONFIG_HOME, or --identity-file"
    )
}

fn cert_fingerprint(certificate_der: &[u8]) -> String {
    let hash = digest::digest(&digest::SHA256, certificate_der);
    let hex = hash
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    format!("sha256:{hex}")
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn uuid_simple() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    format!("{now:x}-{pid:x}")
}

fn set_owner_only_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let perms = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, perms)
            .with_context(|| format!("failed to set permissions on '{}'", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::load_or_create_identity;

    #[test]
    fn load_or_create_identity_reuses_existing_identity() {
        let base = std::env::temp_dir().join(format!(
            "meshque-identity-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let path = base.join("identity.json");

        let first = load_or_create_identity(Some(&path)).unwrap();
        let second = load_or_create_identity(Some(&path)).unwrap();

        assert_eq!(first.peer_id, second.peer_id);
        assert_eq!(first.fingerprint, second.fingerprint);
        assert_eq!(first.certificate_der, second.certificate_der);
        assert_eq!(first.private_key_der, second.private_key_der);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&base);
    }
}
