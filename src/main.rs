//! github-gateway-rs — facade Rust devant l'upstream docker fige v1.12.0.
//!
//! Miroir de `github_gateway` Python : validation Bearer + politique explicite
//! 59R/35W/0admin + proxy vers `127.0.0.1:8800` avec PAT injecte.
//!
//! Environnement (prefixe `GITHUB_MCP_RS_*`) :
//! * `GITHUB_MCP_RS_ISSUER` (defaut issuer prod, HTTPS requis),
//! * `GITHUB_MCP_RS_UPSTREAM` (defaut `http://127.0.0.1:8800`, loopback requis),
//! * `GITHUB_MCP_RS_PORT` (defaut `18999` canary ; `8799` a la bascule),
//! * `GITHUB_MCP_RS_TOKEN` (Bearer statique DEDIE, >= 32 car.) OU
//!   `GITHUB_MCP_RS_TOKEN_FILE` (defaut `/opt/github-gateway-rs/.mcp_token`)
//!   — fail-closed si absent/trop court. JAMAIS le Bearer prod compromis :
//!   le canary utilise son propre secret (rotation prod = gate exploitant),
//! * `GITHUB_MCP_RS_UPSTREAM_TOKEN` / `GITHUB_MCP_RS_UPSTREAM_TOKEN_FILE`
//!   (defaut `/srv/github/secrets/github-pat`, lu sur le VPS uniquement,
//!   jamais journalise) — absent = demarrage OK mais relais fail-closed,
//! * `GITHUB_MCP_RS_TOKEN_SCOPES` (defaut lecture+ecriture, cf. lecon lot 2 :
//!   valeur quotée dans l'unit systemd),
//! * `GITHUB_MCP_RS_CONSENT_HASH` (empreinte PBKDF2, vide = consentement refuse).

use github_gateway_rs::{
    build_router, ServiceConfig, UpstreamToken, ISSUER_DEFAULT, READ_SCOPE, RESOURCE_NAME,
    RESOURCE_URL, WRITE_SCOPE,
};
use mcp_auth::oauth::OAuthConfig;

/// Charge un secret : variable directe, sinon fichier. `requis` = fail-closed
/// (erreur) si absent ; sinon `None` (ex. PAT : relais fail-closed, demarrage OK).
fn load_secret(
    direct_var: &str,
    file_var: &str,
    default_file: &str,
    requis: bool,
) -> Result<Option<String>, String> {
    if let Ok(v) = std::env::var(direct_var) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            if v.len() < 32 {
                return Err(format!("{direct_var} trop court (<32 car.)"));
            }
            return Ok(Some(v));
        }
    }
    let path = std::env::var(file_var)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default_file.to_string());
    match std::fs::read_to_string(&path) {
        Ok(raw) => {
            let tok = raw.trim().to_string();
            if tok.len() < 32 {
                return Err(format!("secret trop court (<32 car.), refuse ({path})"));
            }
            Ok(Some(tok))
        }
        Err(e) => {
            if requis {
                Err(format!("secret illisible ({path}) : {e}"))
            } else {
                Ok(None)
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    mcp_observe::init("github-gateway-rs");

    // Defauts prod-conformes si l'exploitant ne pose que les secrets.
    if std::env::var("GITHUB_MCP_RS_ISSUER")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        // `set_var` est `unsafe` sur cette toolchain : init mono-thread.
        unsafe { std::env::set_var("GITHUB_MCP_RS_ISSUER", ISSUER_DEFAULT) };
    }
    if std::env::var("GITHUB_MCP_RS_UPSTREAM")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        unsafe { std::env::set_var("GITHUB_MCP_RS_UPSTREAM", "http://127.0.0.1:8800") };
    }
    let token = load_secret(
        "GITHUB_MCP_RS_TOKEN",
        "GITHUB_MCP_RS_TOKEN_FILE",
        "/opt/github-gateway-rs/.mcp_token",
        true,
    )
    .map_err(|e| {
        tracing::error!("fail-closed: pas de Bearer valide");
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e)
    })?
    .expect("Bearer requis");
    unsafe { std::env::set_var("GITHUB_MCP_RS_TOKEN", &token) };

    // Lecon lot 2 : sans SCOPES explicites, le defaut install ne donne que la
    // lecture. Le canary parite exige lecture+ecriture.
    if std::env::var("GITHUB_MCP_RS_TOKEN_SCOPES")
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        unsafe {
            std::env::set_var(
                "GITHUB_MCP_RS_TOKEN_SCOPES",
                format!("{READ_SCOPE} {WRITE_SCOPE}"),
            )
        };
    }

    let env = mcp_gateway::config::from_prefix(
        "GITHUB_MCP_RS",
        18999,
        READ_SCOPE,
        &[READ_SCOPE, WRITE_SCOPE],
    )?;

    // PAT upstream : fichier 600 existant partage en lecture seule (VPS).
    // Absent = demarrage OK, relais refuse en fail-closed (comme le Python).
    let upstream_token = load_secret(
        "GITHUB_MCP_RS_UPSTREAM_TOKEN",
        "GITHUB_MCP_RS_UPSTREAM_TOKEN_FILE",
        "/srv/github/secrets/github-pat",
        false,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?
    .map(UpstreamToken::new);

    let port = env.port;
    let upstream_log = env.upstream.clone();
    let pat_state = if upstream_token.is_some() {
        "configure"
    } else {
        "missing"
    };
    let app = build_router(ServiceConfig {
        upstream: env.upstream,
        upstream_token,
        static_token: env.static_token,
        static_token_scopes: env.token_scopes,
        oauth: OAuthConfig {
            issuer: env.issuer,
            resource_url: RESOURCE_URL.to_string(),
            resource_name: RESOURCE_NAME.to_string(),
            default_scope: READ_SCOPE.to_string(),
            valid_scopes: vec![READ_SCOPE.to_string(), WRITE_SCOPE.to_string()],
            extra_submit_scopes: vec![WRITE_SCOPE.to_string()],
            consent_hash: env.consent_hash,
            static_client_id: "github-mcp-cli-statique".to_string(),
        },
        max_body_bytes: mcp_http::hardening::DEFAULT_MAX_BODY_BYTES,
    })?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    tracing::info!(
        port,
        upstream = %upstream_log,
        pat = pat_state,
        "github-gateway-rs prete (boucle locale uniquement)"
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(mcp_core::lifecycle::shutdown_signal())
        .await?;
    Ok(())
}
