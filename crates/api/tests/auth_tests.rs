use crate::common::TestContext;
use crate::common::fixtures::sample_login_request;
use chamber_api::models::{ApiResponse, ItemWithValueResponse, LoginRequest, LoginResponse};
use http::StatusCode;
use serde_json::json;
mod common;

// ============================================================================
// Login Tests
// ============================================================================

#[tokio::test]
async fn test_login_success() -> color_eyre::Result<()> {
    // Create a completely isolated test context
    let ctx = TestContext::new()?;

    let login_request = sample_login_request();
    let response = ctx.server.post("/api/v1/auth/login").json(&login_request).await;

    response.assert_status_ok();

    let body: ApiResponse<LoginResponse> = response.json();
    assert!(!body.data.token.is_empty(), "Token should not be empty");
    assert!(!body.data.scopes.is_empty(), "Scopes should not be empty");
    assert!(body.data.expires_at > chrono::Utc::now(), "Token should not be expired");

    // Verify token contains expected scopes
    let expected_scopes = ["read:items", "write:items", "manage:vaults"];
    for scope in expected_scopes {
        assert!(
            body.data.scopes.contains(&scope.to_string()),
            "Token should contain scope: {scope}"
        );
    }
    Ok(())
    // TempDir automatically cleans up when ctx goes out of scope
}

#[tokio::test]
async fn test_login_invalid_password() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let login_request = LoginRequest {
        master_password: "wrong_password".to_string(),
    };

    let response = ctx.server.post("/api/v1/auth/login").json(&login_request).await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_login_empty_password() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let login_request = LoginRequest {
        master_password: String::new(),
    };

    let response = ctx.server.post("/api/v1/auth/login").json(&login_request).await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_login_malformed_request() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    // Missing master_password field
    let malformed_request = json!({
        "password": "some_password"  // wrong field name
    });

    let response = ctx.server.post("/api/v1/auth/login").json(&malformed_request).await;
    response.assert_status(StatusCode::UNPROCESSABLE_ENTITY);

    Ok(())
}

// ============================================================================
// Token Validation Tests
// ============================================================================

#[tokio::test]
async fn test_protected_endpoint_with_valid_token() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;

    response.assert_status_ok();

    Ok(())
}

#[tokio::test]
async fn test_protected_endpoint_without_token() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx.server.get("/api/v1/items").await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_protected_endpoint_with_invalid_token() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx
        .server
        .get("/api/v1/items")
        .authorization_bearer("invalid_token")
        .await;

    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_protected_endpoint_with_malformed_bearer() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx
        .server
        .get("/api/v1/items")
        .add_header("Authorization", "Bearer") // Missing token
        .await;

    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_protected_endpoint_with_wrong_auth_scheme() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx
        .server
        .get("/api/v1/items")
        .add_header("Authorization", "Basic dGVzdDp0ZXN0") // Basic auth instead of Bearer
        .await;

    response.assert_status_unauthorized();

    Ok(())
}

// ============================================================================
// Session Management Tests
// ============================================================================

#[tokio::test]
async fn test_session_lock_success() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let response = ctx
        .server
        .post("/api/v1/session/lock")
        .authorization_bearer(&token)
        .await;

    response.assert_status_ok();

    // The token issued before lock must be rejected on the next call.
    let items_response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;
    items_response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_session_lock_without_auth() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx.server.post("/api/v1/session/lock").await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_session_unlock_success() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    // Lock invalidates the token that was just issued.
    let lock_response = ctx
        .server
        .post("/api/v1/session/lock")
        .authorization_bearer(&token)
        .await;
    lock_response.assert_status_ok();

    let unlock_request = json!({
        "master_password": ctx.master_password
    });

    let response = ctx
        .server
        .post("/api/v1/session/unlock")
        .authorization_bearer(&token)
        .json(&unlock_request)
        .await;

    response.assert_status_unauthorized();

    // A new login unlocks the vault and can read items again.
    let new_token = ctx.login().await?;
    let items_response = ctx.server.get("/api/v1/items").authorization_bearer(&new_token).await;
    items_response.assert_status_ok();

    Ok(())
}

#[tokio::test]
async fn test_session_unlock_invalid_password() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let unlock_request = json!({
        "master_password": "wrong_password"
    });

    let response = ctx
        .server
        .post("/api/v1/session/unlock")
        .authorization_bearer(&token)
        .json(&unlock_request)
        .await;

    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_session_unlock_without_auth() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let unlock_request = json!({
        "master_password": ctx.master_password
    });

    let response = ctx.server.post("/api/v1/session/unlock").json(&unlock_request).await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_logout_success() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let response = ctx
        .server
        .post("/api/v1/auth/logout")
        .authorization_bearer(&token)
        .await;

    response.assert_status_ok();

    // The token issued before logout must be rejected on the next call.
    let items_response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;
    items_response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_logout_without_auth() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;

    let response = ctx.server.post("/api/v1/auth/logout").await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_token_issued_before_logout_is_rejected() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let logout = ctx.server.post("/api/v1/auth/logout").authorization_bearer(&token).await;
    logout.assert_status_ok();

    let response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_token_issued_before_session_lock_is_rejected() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let lock = ctx.server.post("/api/v1/session/lock").authorization_bearer(&token).await;
    lock.assert_status_ok();

    let response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_logout_blocks_item_decrypt_until_unlock() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;
    let secret = "logout-secret-value-not-for-locked-session";
    let item_id = ctx.create_test_item("logout-secret", "note", secret).await?;

    let logout = ctx.server.post("/api/v1/auth/logout").authorization_bearer(&token).await;
    logout.assert_status_ok();

    let denied = ctx
        .server
        .get(&format!("/api/v1/items/{item_id}/value"))
        .authorization_bearer(&token)
        .await;
    denied.assert_status_unauthorized();
    assert!(
        !denied.text().contains(secret),
        "item routes must not return the secret after logout"
    );

    let new_token = ctx.login().await?;
    let revealed = ctx
        .server
        .get(&format!("/api/v1/items/{item_id}/value"))
        .authorization_bearer(&new_token)
        .await;
    revealed.assert_status_ok();
    let body: ApiResponse<ItemWithValueResponse> = revealed.json();
    assert_eq!(body.data.value, secret);

    Ok(())
}

#[tokio::test]
async fn test_session_lock_blocks_item_decrypt_until_unlock() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;
    let secret = "lock-secret-value-not-for-locked-session";
    let item_id = ctx.create_test_item("lock-secret", "note", secret).await?;

    let lock = ctx.server.post("/api/v1/session/lock").authorization_bearer(&token).await;
    lock.assert_status_ok();

    let denied = ctx
        .server
        .get(&format!("/api/v1/items/{item_id}/value"))
        .authorization_bearer(&token)
        .await;
    denied.assert_status_unauthorized();
    assert!(
        !denied.text().contains(secret),
        "item routes must not return the secret after session lock"
    );

    let new_token = ctx.login().await?;
    let revealed = ctx
        .server
        .get(&format!("/api/v1/items/{item_id}/value"))
        .authorization_bearer(&new_token)
        .await;
    revealed.assert_status_ok();
    let body: ApiResponse<ItemWithValueResponse> = revealed.json();
    assert_eq!(body.data.value, secret);

    Ok(())
}

#[tokio::test]
async fn test_login_expires_at_is_about_one_hour() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;
    let before = chrono::Utc::now();

    let response = ctx.server.post("/api/v1/auth/login").json(&sample_login_request()).await;
    response.assert_status_ok();

    let body: ApiResponse<LoginResponse> = response.json();
    let minutes = body.data.expires_at.signed_duration_since(before).num_minutes();
    assert!(
        (45..=90).contains(&minutes),
        "login expires_at should be about 1 hour, got {minutes} minutes"
    );

    Ok(())
}

// ============================================================================
// Scope-based Authorization Tests
// ============================================================================

#[tokio::test]
async fn test_scope_read_items() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    // Should be able to list items (requires read:items scope)
    let response = ctx.server.get("/api/v1/items").authorization_bearer(&token).await;

    response.assert_status_ok();

    Ok(())
}

#[tokio::test]
async fn test_scope_write_items() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    let create_request = json!({
        "name": "test_item",
        "kind": "note",
        "value": "test_value"
    });

    // Should be able to create items (requires write:items scope)
    let response = ctx
        .server
        .post("/api/v1/items")
        .authorization_bearer(&token)
        .json(&create_request)
        .await;

    response.assert_status_ok();

    Ok(())
}

#[tokio::test]
async fn test_scope_manage_vaults() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    // Should be able to list vaults (requires manage:vaults scope)
    let response = ctx.server.get("/api/v1/vaults").authorization_bearer(&token).await;

    response.assert_status_ok();

    Ok(())
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

/*#[tokio::test]
async fn test_multiple_concurrent_logins() -> color_eyre::Result<()> {
    let ctx = TestContext::new()?;
    let login_request = sample_login_request();

    // Perform multiple concurrent login requests
    let responses = futures:: ::join_all((0..5).map(|_| {
        ctx.server.post("/api/v1/auth/login").json(&login_request)
    })).await;

    // All should succeed
    for response in responses {
        response.assert_status_ok();
    }

    Ok(())
}*/

#[tokio::test]
async fn test_token_after_server_restart() -> color_eyre::Result<()> {
    // Note: This test would be more complex to implement properly as it would
    // require actually restarting the test server. For now, we can simulate
    // the scenario by creating a new TestContext with the same vault data.

    let mut ctx1 = TestContext::new()?;
    let token = ctx1.login().await?;

    // Create a new context (simulating server restart)
    // In a real scenario, tokens should be invalidated after restart
    // since the signing secret would be regenerated
    let ctx2 = TestContext::new()?;

    let response = ctx2.server.get("/api/v1/items").authorization_bearer(&token).await;

    // Token should be invalid with new server instance
    response.assert_status_unauthorized();

    Ok(())
}

#[tokio::test]
async fn test_case_insensitive_bearer_header() -> color_eyre::Result<()> {
    let mut ctx = TestContext::new()?;
    let token = ctx.login().await?;

    // Test with lowercase 'bearer'
    let response = ctx
        .server
        .get("/api/v1/items")
        .add_header("Authorization", &format!("bearer {token}"))
        .await;

    // Should still work (HTTP headers are case-insensitive)
    response.assert_status_ok();

    Ok(())
}
