use eal_api_server::transport::{DIRECT_ALERTS_SQL, MAX_FRAME_BYTES};
use eal_web_server::gateway::{GATEWAY_MODES, validate_nats_url, validate_service_url};

const SHARED_AUTH_REV: &str = "a814cf34eeef3429e5dee36f45965b6958d694bb";
const ORES_REV: &str = "ca176fb6768a9750d262a536952268625ffd3a8a";
const API_REV: &str = "882d1e92e623805dffeba9e5f5597f164a4b6fb3";

#[test]
fn official_security_dependencies_are_immutable() {
    let manifest = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    assert!(manifest.contains(SHARED_AUTH_REV));
    assert!(manifest.contains(ORES_REV));
    assert!(manifest.contains(API_REV));
    assert!(manifest.contains("rev ="));
}

#[test]
fn all_four_modes_are_explicit_and_bounded() {
    assert_eq!(
        GATEWAY_MODES,
        [
            "direct_db",
            "stateless_https",
            "stateful_mtls_tcp",
            "jetstream_async"
        ]
    );
    assert_eq!(MAX_FRAME_BYTES, 64 * 1024);
    assert!(validate_service_url("https://api.example.test").is_ok());
    assert!(validate_service_url("http://api.ns.svc.cluster.local:8080").is_ok());
    assert!(validate_service_url("http://api.example.test").is_err());
    assert!(validate_service_url("https://user:secret@api.example.test").is_err());
    assert!(validate_nats_url("tls://nats.example.test:4222").is_ok());
    assert!(validate_nats_url("nats://localhost:4222").is_ok());
    assert!(validate_nats_url("nats://nats.example.test:4222").is_err());
}

#[test]
fn direct_projection_has_no_write_surface() {
    let sql = DIRECT_ALERTS_SQL.trim().to_ascii_uppercase();
    assert!(sql.starts_with("SELECT "));
    assert!(DIRECT_ALERTS_SQL.contains("product_tenant = $1"));
    assert!(DIRECT_ALERTS_SQL.contains("owner_subject = $2"));
    for forbidden in ["INSERT ", "UPDATE ", "DELETE ", "ALTER ", "DROP ", ";"] {
        assert!(!sql.contains(forbidden));
    }
}
