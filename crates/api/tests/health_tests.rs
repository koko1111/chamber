mod common;

use crate::common::TestContext;
use chamber_api::models::{ApiResponse, HealthResponse};
use chamber_api::{HealthReportResponse, StatsResponse};
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[tokio::test]
async fn test_health_endpoint() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx.server.get("/api/v1/health").await;
    response.assert_status_ok();

    let body: ApiResponse<HealthResponse> = response.json();
    assert_eq!(body.data.status, "ok");
    assert!(!body.data.version.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_health_report() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    ctx.login().await?;
    ctx.unlock_session().await?;

    // Create some test passwords with security issues
    ctx.create_test_item("Weak Password", "password", "123").await?; // Short password
    ctx.create_test_item("Another Password", "password", "password123")
        .await?; // Common pattern
    ctx.create_test_item("Good Password", "password", "super_secure_password_with_numbers_123!@#")
        .await?;

    let response = ctx
        .server
        .get("/api/v1/health/report")
        .authorization_bearer(ctx.auth_token.as_ref().unwrap())
        .await;

    response.assert_status_ok();

    let body: ApiResponse<HealthReportResponse> = response.json();
    assert!(body.data.total_items > 0);
    assert!(body.data.password_items > 0);
    assert!(body.data.security_score >= 0.0 && body.data.security_score <= 100.0);

    Ok(())
}

#[tokio::test]
async fn test_stats_endpoint() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    ctx.login().await?;
    ctx.unlock_session().await?;

    // Create diverse items
    ctx.create_test_item("Password", "password", "pass123").await?;
    ctx.create_test_item("Note", "note", "Some note content").await?;
    ctx.create_test_item("Card", "creditcard", "4111111111111111").await?;

    let response = ctx
        .server
        .get("/api/v1/stats")
        .authorization_bearer(ctx.auth_token.as_ref().unwrap())
        .await;

    response.assert_status_ok();

    let body: ApiResponse<StatsResponse> = response.json();
    assert_eq!(body.data.total_items, 3);
    assert_eq!(body.data.password_items, 1);
    assert_eq!(body.data.note_items, 1);
    assert_eq!(body.data.card_items, 1);
    assert!(body.data.vault_size_bytes > 0);

    Ok(())
}

#[tokio::test]
async fn test_health_report_omits_password_digest() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    ctx.login().await?;
    ctx.unlock_session().await?;

    let secret = "SENTINEL-REUSED-PASSWORD-xyz";
    ctx.create_test_item("Reuse A", "password", secret).await?;
    ctx.create_test_item("Reuse B", "password", secret).await?;
    ctx.create_test_item("Unique Password", "password", "different-password-value-999")
        .await?;

    let response = ctx
        .server
        .get("/api/v1/health/report")
        .authorization_bearer(ctx.auth_token.as_ref().unwrap())
        .await;

    response.assert_status_ok();
    let text = response.text();
    let md5_digest = format!("{:x}", md5::compute(secret.as_bytes()));
    assert!(!text.contains(&md5_digest), "health report returned an MD5 digest");
    assert!(!text.contains(secret), "health report returned secret characters");
    assert!(
        !text.contains("password_hash"),
        "health report serialized the digest field"
    );

    let signing_key = ctx.auth.signing_key_bytes().expect("signing key");
    let mut mac = Hmac::<Sha256>::new_from_slice(&signing_key).expect("hmac key");
    mac.update(secret.as_bytes());
    let hmac_digest = hex_encode(&mac.finalize().into_bytes());
    assert!(!text.contains(&hmac_digest), "health report returned the keyed digest");

    let body: ApiResponse<HealthReportResponse> = serde_json::from_str(&text)?;
    let group = body
        .data
        .reused_passwords
        .iter()
        .find(|group| group.item_names.iter().any(|name| name == "Reuse A"))
        .expect("reused passwords should still be grouped");
    assert!(group.item_names.iter().any(|name| name == "Reuse B"));
    assert!(!group.item_names.iter().any(|name| name == "Unique Password"));

    Ok(())
}

#[tokio::test]
async fn test_cors_rejects_non_loopback_origin() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let rejected = ctx
        .server
        .get("/api/v1/health")
        .add_header("origin", "https://evil.example")
        .await;
    rejected.assert_status_ok();
    let allow = rejected
        .headers()
        .get("access-control-allow-origin")
        .and_then(|value| value.to_str().ok());
    assert_ne!(allow, Some("https://evil.example"));
    assert_ne!(allow, Some("*"), "wildcard CORS must not accept a non-loopback origin");

    let allowed = ctx
        .server
        .get("/api/v1/health")
        .add_header("origin", "http://127.0.0.1:4173")
        .await;
    allowed.assert_status_ok();
    let loopback = allowed
        .headers()
        .get("access-control-allow-origin")
        .and_then(|value| value.to_str().ok());
    assert_eq!(loopback, Some("http://127.0.0.1:4173"));

    let localhost = ctx
        .server
        .get("/api/v1/health")
        .add_header("origin", "http://localhost:3000")
        .await;
    assert_eq!(
        localhost
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("http://localhost:3000")
    );

    let ipv6 = ctx
        .server
        .get("/api/v1/health")
        .add_header("origin", "http://[::1]:3000")
        .await;
    assert_eq!(
        ipv6.headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("http://[::1]:3000")
    );

    Ok(())
}
