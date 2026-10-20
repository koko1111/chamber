use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method, header::CONTENT_TYPE},
    middleware,
    routing::{delete, get, patch, post, put},
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{info, warn};

use crate::auth::{AuthState, auth_middleware};
use crate::handlers;
use chamber_vault::{Vault, VaultManager};

pub struct ApiServer {
    app: Router,
    listener: TcpListener,
}

#[derive(Clone)]
pub struct AppState {
    pub vault: Arc<tokio::sync::Mutex<Vault>>,
    pub vault_manager: Arc<tokio::sync::Mutex<VaultManager>>,
    pub auth: AuthState,
}

impl ApiServer {
    /// # Errors
    /// This function will return an error if:
    /// - The TCP binding to the specified address fails.
    /// - There are issues configuring the router.
    pub async fn new(vault: Vault, vault_manager: VaultManager, bind_address: &str) -> color_eyre::Result<Self> {
        let state = AppState {
            vault: Arc::new(tokio::sync::Mutex::new(vault)),
            vault_manager: Arc::new(tokio::sync::Mutex::new(vault_manager)),
            auth: AuthState::new(),
        };

        let app = build_router(Arc::new(state))?;

        let listener = TcpListener::bind(bind_address).await?;
        info!("API server will bind to: {}", bind_address);

        Ok(Self { app, listener })
    }

    /// # Errors
    /// This function will return an error if:
    /// - Retrieving the local socket's address fails.
    /// - Axum fails to serve the application.
    pub async fn serve(self) -> color_eyre::Result<()> {
        let addr = self.listener.local_addr()?;
        info!("API server listening on http://{}", addr);
        warn!("{}", bind_warning(addr));

        axum::serve(self.listener, self.app).await?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if getting the local address from the TCP listener fails.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }
}

/// # Errors
///
/// Returns an error if there are any issues configuring the router or applying the middleware.
pub fn build_router(state: Arc<AppState>) -> color_eyre::Result<Router> {
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::PATCH])
        .allow_headers([CONTENT_TYPE])
        .allow_origin(AllowOrigin::predicate(|origin, _parts| is_loopback_origin(origin)));

    let app = Router::new()
        .route("/api/v1/health", get(handlers::health))
        // Authentication endpoints (no auth middleware needed)
        .route("/api/v1/auth/login", post(handlers::login))
        .route("/api/v1/session/unlock", post(handlers::session_unlock))
        // Protected endpoints - these will have the auth middleware applied
        .route("/api/v1/auth/logout", post(handlers::logout))
        .route("/api/v1/session/lock", post(handlers::session_lock))
        // Items
        .route("/api/v1/items", get(handlers::list_items))
        .route("/api/v1/items", post(handlers::create_item))
        .route("/api/v1/items/search", get(handlers::search_items))
        .route("/api/v1/items/counts", get(handlers::get_counts))
        .route("/api/v1/items/{id}", get(handlers::get_item))
        .route("/api/v1/items/{id}", put(handlers::update_item))
        .route("/api/v1/items/{id}", delete(handlers::delete_item))
        .route("/api/v1/items/{id}/value", get(handlers::get_item_value))
        .route("/api/v1/items/{id}/copy", post(handlers::copy_item_to_clipboard))
        // Password generation
        .route("/api/v1/passwords/generate", post(handlers::generate_password))
        .route(
            "/api/v1/passwords/memorable",
            post(handlers::generate_memorable_password_handler),
        )
        // Import/Export
        .route("/api/v1/import", post(handlers::import_items_handler))
        .route("/api/v1/export", post(handlers::export_items_handler))
        .route("/api/v1/import/dry-run", post(handlers::dry_run_import))
        // Vault management
        .route("/api/v1/vaults", get(handlers::list_vaults))
        .route("/api/v1/vaults", post(handlers::create_vault))
        .route("/api/v1/vaults/{id}/switch", post(handlers::switch_vault))
        .route("/api/v1/vaults/{id}", patch(handlers::update_vault))
        .route("/api/v1/vaults/{id}", delete(handlers::delete_vault))
        .route("/api/v1/health/report", get(handlers::health_report))
        .route("/api/v1/stats", get(handlers::stats))
        .layer(middleware::from_fn_with_state(Arc::clone(&state), auth_middleware))
        .layer(cors)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(state);

    Ok(app)
}

fn bind_warning(addr: SocketAddr) -> String {
    if addr.ip().is_loopback() {
        "API server is running on localhost only - not accessible from other machines".to_string()
    } else {
        format!("API server bind address {addr} is not loopback")
    }
}

fn is_loopback_origin(origin: &HeaderValue) -> bool {
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Some((_, rest)) = origin.split_once("://") else {
        return false;
    };
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host_port.is_empty() {
        return false;
    }
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn localhost_warning_matches_bind_address() {
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert!(bind_warning(loopback).contains("localhost only"));

        let unspecified = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
        let warning = bind_warning(unspecified);
        assert!(warning.contains("not loopback"));
        assert!(!warning.contains("localhost only"));

        let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1);
        assert!(bind_warning(ipv6).contains("localhost only"));
    }

    #[test]
    fn cors_origin_allows_loopback_only() {
        let allowed = [
            "http://localhost",
            "http://localhost:3000",
            "https://127.0.0.1:4173",
            "http://[::1]:3000",
            "http://LocalHost:9",
        ];
        for origin in allowed {
            let value = HeaderValue::from_str(origin).unwrap();
            assert!(is_loopback_origin(&value), "{origin} should be accepted");
        }

        let rejected = [
            "https://evil.example",
            "http://192.168.1.10:3000",
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            "null",
        ];
        for origin in rejected {
            let value = HeaderValue::from_str(origin).unwrap();
            assert!(!is_loopback_origin(&value), "{origin} should be rejected");
        }
    }
}
