//! Bibliotheque partagee `github-gateway-rs` (contrat + politique + assemblage).
//!
//! Miroir de `github_gateway` Python : validation Bearer + politique explicite
//! 59 lectures / 35 ecritures / 0 admin + proxy vers l'upstream docker fige
//! `github-mcp-server:v1.12.0` (`:8800`, loopback, PAT injecte).
//!
//! Differences assumees vs `build_gateway` du framework (metier local au
//! depot, jamais dans le framework) :
//! * relais avec injection du PAT upstream (`Authorization: Bearer …`, fichier
//!   600 charge au demarrage, jamais journalise) ; sans PAT : demarrage OK
//!   mais relais refuse en fail-closed (-32000), comme le Python ;
//! * compatibilite stricte Go v1.12.0 (`compat`) : normalisation `Accept`,
//!   coherence `mcp-protocol-version`, strip `_meta` non supportee ;
//! * `get_file_contents` normalise en texte direct (`file_norm`,
//!   anti-materialisation ChatGPT), a l'identique du Python ;
//! * `/health` (+ `/ready`) au format Python exact, `upstream_auth`
//!   `configure`/`missing` inclus (jamais la valeur) ;
//! * challenge 401 vers l'URL PRM exacte du Python.
//!
//! OAuth JWT/Python vs opaque/Rust : canary via Bearer statique dedie
//! (meme famille que les lots 1-2, bascule gated).

pub mod compat;
pub mod file_norm;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{middleware, routing::get, Json, Router};
use serde_json::{json, Value};
use zeroize::Zeroize;

use mcp_auth::bearer::{bearer_middleware, json_response, BearerState, StaticBearer, TokenScopes};
use mcp_auth::filestore::{ChainedResolver, FileStore};
use mcp_auth::oauth::{
    auth_router, protected_resource_router, MemoryStore, OAuthConfig, OAuthState,
};
use mcp_auth::policy::{decide_body, CallDecision, TablePolicy, ToolClass, ToolPolicy};
use mcp_core::error::{self, codes};

/// Outils de lecture (aucune donnee GitHub modifiee, 59, v1.12.0).
pub const OUTILS_LECTURE: &[&str] = &[
    "actions_get",
    "actions_list",
    "custom_properties_read",
    "get_code_quality_finding",
    "get_code_scanning_alert",
    "get_commit",
    "get_copilot_space",
    "get_dependabot_alert",
    "get_discussion",
    "get_discussion_comments",
    "get_file_contents",
    "get_gist",
    "get_global_security_advisory",
    "get_job_logs",
    "get_label",
    "get_latest_release",
    "get_me",
    "get_notification_details",
    "get_release_by_tag",
    "get_repository_tree",
    "get_secret_scanning_alert",
    "get_tag",
    "get_team_members",
    "get_teams",
    "github_support_docs_search",
    "issue_read",
    "list_branches",
    "list_code_scanning_alerts",
    "list_commits",
    "list_copilot_spaces",
    "list_dependabot_alerts",
    "list_discussion_categories",
    "list_discussions",
    "list_gists",
    "list_global_security_advisories",
    "list_issue_fields",
    "list_issue_types",
    "list_issues",
    "list_label",
    "list_notifications",
    "list_org_repository_security_advisories",
    "list_pull_requests",
    "list_releases",
    "list_repository_collaborators",
    "list_repository_security_advisories",
    "list_secret_scanning_alerts",
    "list_starred_repositories",
    "list_tags",
    "projects_get",
    "projects_list",
    "pull_request_read",
    "repository_ruleset_read",
    "search_code",
    "search_commits",
    "search_issues",
    "search_orgs",
    "search_pull_requests",
    "search_repositories",
    "search_users",
];

/// Mutateurs (35, v1.12.0). `delete_repository` reste accessible en ecriture
/// (gate MRTR cote upstream officiel, comme le Python).
pub const OUTILS_ECRITURE: &[&str] = &[
    "actions_run_trigger",
    "add_comment_to_pending_review",
    "add_issue_comment",
    "add_reply_to_pull_request_comment",
    "assign_copilot_to_issue",
    "assign_copilot_to_issue_with_intent",
    "create_branch",
    "create_gist",
    "create_or_update_file",
    "create_pull_request",
    "create_pull_request_with_copilot",
    "create_repository",
    "create_repository_ruleset",
    "custom_properties_write",
    "delete_file",
    "delete_repository",
    "discussion_comment_write",
    "dismiss_notification",
    "fork_repository",
    "issue_write",
    "label_write",
    "manage_notification_subscription",
    "manage_repository_notification_subscription",
    "mark_all_notifications_read",
    "merge_pull_request",
    "projects_write",
    "pull_request_review_write",
    "push_files",
    "request_copilot_review",
    "star_repository",
    "sub_issue_write",
    "unstar_repository",
    "update_gist",
    "update_pull_request",
    "update_pull_request_branch",
];

pub const READ_SCOPE: &str = "github:lecture";
pub const WRITE_SCOPE: &str = "github:ecriture";

/// URLs publiques a l'identique du Python (`app.py`/`oauth.py`).
pub const ISSUER_DEFAULT: &str = "https://mymcps.duckdns.org/oauth/github";
pub const RESOURCE_URL: &str = "https://mymcps.duckdns.org/github/mcp";
pub const RESOURCE_NAME: &str = "GitHub MCP (passerelle)";
pub const PRM_ALIAS: &str = "/.well-known/oauth-protected-resource/github/mcp";
/// URL PRM exacte servie par le Python (challenge 401 + document).
pub const PRM_URL: &str =
    "https://mymcps.duckdns.org/.well-known/oauth-protected-resource/github/mcp";

/// Politique fail-closed du service (59R/35W/0admin, inconnu refuse).
pub fn policy() -> TablePolicy {
    let mut entries: Vec<(&str, ToolClass)> = Vec::with_capacity(94);
    for t in OUTILS_LECTURE {
        entries.push((t, ToolClass::Read));
    }
    for t in OUTILS_ECRITURE {
        entries.push((t, ToolClass::Write));
    }
    TablePolicy::new(READ_SCOPE, WRITE_SCOPE, &entries)
}

/// PAT upstream (jamais journalise, zeroise a la destruction).
#[derive(Clone)]
pub struct UpstreamToken(String);

impl UpstreamToken {
    pub fn new(token: String) -> Self {
        Self(token)
    }
}

impl Drop for UpstreamToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for UpstreamToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UpstreamToken(REDACTED)")
    }
}

/// Configuration d'assemblage (resolue par le binaire).
pub struct ServiceConfig {
    pub upstream: String,
    /// `None` = credential GitHub absent : demarrage OK, relais fail-closed.
    pub upstream_token: Option<UpstreamToken>,
    pub static_token: String,
    pub static_token_scopes: Vec<String>,
    pub oauth: OAuthConfig,
    pub max_body_bytes: usize,
}

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    upstream: String,
    upstream_token: Option<UpstreamToken>,
    policy: Arc<TablePolicy>,
}

#[derive(Clone)]
struct HealthState {
    service: String,
    upstream_configured: bool,
}

async fn health_handler(State(s): State<HealthState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": s.service,
        "mcp": "/mcp",
        "upstream_auth": if s.upstream_configured { "configure" } else { "missing" },
    }))
}

/// Assemble le routeur complet : sante + OAuth + PRM (+ alias) + `/mcp`
/// (Bearer puis politique puis relais PAT upstream) + 404.
pub fn build_router(cfg: ServiceConfig) -> Result<Router, mcp_core::error::Error> {
    build_router_full(cfg, None)
}

/// Assemble le routeur avec pont fichier optionnel (sessions OAuth Python
/// existantes acceptées sans re-consentement ; `None` = comme
/// [`build_router`]). Le Bearer statique et le PAT upstream sont inchangés
/// (aucune rotation : gate exploitant).
pub fn build_router_with_filestore(
    cfg: ServiceConfig,
    mount: Option<mcp_gateway::router::FileStoreMount>,
) -> Result<Router, mcp_core::error::Error> {
    build_router_full(cfg, mount)
}

fn build_router_full(
    cfg: ServiceConfig,
    mount: Option<mcp_gateway::router::FileStoreMount>,
) -> Result<Router, mcp_core::error::Error> {
    let store = Arc::new(MemoryStore::default());
    let file = mount
        .filter(|m| !m.etat_path.trim().is_empty())
        .map(|m| Arc::new(FileStore::new(&m.etat_path)));
    let chained = Arc::new(ChainedResolver::new(Arc::clone(&store), file));
    let oauth_state = OAuthState {
        config: Arc::new(cfg.oauth.clone()),
        store,
    };
    let bearer_state = BearerState::new(
        StaticBearer::new(
            &cfg.static_token,
            "github-mcp-cli-statique",
            &cfg.static_token_scopes,
        ),
        chained,
        vec![READ_SCOPE.to_string()],
        PRM_URL.to_string(),
    );
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| mcp_core::error::Error::Upstream(e.to_string()))?;
    let health = HealthState {
        service: "github-gateway-rs".to_string(),
        upstream_configured: cfg.upstream_token.is_some(),
    };
    let app_state = AppState {
        client,
        upstream: cfg.upstream.trim_end_matches('/').to_string(),
        upstream_token: cfg.upstream_token,
        policy: Arc::new(policy()),
    };

    let mcp_route = Router::new()
        .route(
            "/mcp",
            get(mcp_handler)
                .post(mcp_handler)
                .delete(mcp_handler)
                .route_layer(middleware::from_fn_with_state(
                    bearer_state,
                    bearer_middleware::<ChainedResolver>,
                )),
        )
        .with_state(app_state);

    let health_router = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(health_handler))
        .with_state(health);

    let app = Router::new()
        .merge(health_router)
        .merge(auth_router(oauth_state.clone()))
        .merge(protected_resource_router(oauth_state, &[PRM_ALIAS]))
        .merge(mcp_route);

    Ok(mcp_http::hardening::harden(app, cfg.max_body_bytes))
}

/// Handler `/mcp` : politique AVANT envoi (comme `ProxyMCP._decider`), puis
/// relais avec PAT injecte (jamais l'`Authorization` client).
async fn mcp_handler(State(state): State<AppState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let method = parts.method.clone();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().map(str::to_string);
    let scopes: HashSet<String> = parts
        .extensions
        .get::<TokenScopes>()
        .map(|s| s.0.clone())
        .unwrap_or_default();

    let mut body_bytes: Option<Vec<u8>> = None;
    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        let bytes =
            match axum::body::to_bytes(body, mcp_http::hardening::DEFAULT_MAX_BODY_BYTES).await {
                Ok(b) => b,
                Err(_) => {
                    return json_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        error::payload_too_large_body(),
                    );
                }
            };
        if !bytes.is_empty() {
            match decide_body(&bytes) {
                CallDecision::ParseError => {
                    return json_response(
                        StatusCode::OK,
                        error::jsonrpc_error(
                            None,
                            codes::PARSE,
                            "corps JSON-RPC illisible (fail-closed)",
                        ),
                    );
                }
                CallDecision::BatchRejected => {
                    return json_response(
                        StatusCode::OK,
                        error::jsonrpc_error(
                            None,
                            codes::BATCH,
                            "requetes par lot non prises en charge",
                        ),
                    );
                }
                CallDecision::Nameless { id } => {
                    return json_response(
                        StatusCode::OK,
                        error::jsonrpc_error(
                            id.as_ref(),
                            codes::APP,
                            "tools/call sans nom d'outil (fail-closed)",
                        ),
                    );
                }
                CallDecision::Call { id, name } => {
                    if let Some(reason) = state.policy.autoriser_call(&name, &scopes) {
                        return json_response(
                            StatusCode::OK,
                            error::jsonrpc_error(id.as_ref(), codes::APP, &reason),
                        );
                    }
                }
                CallDecision::Passthrough => {}
            }
            body_bytes = Some(bytes.to_vec());
        }
    }

    // Fail-closed sans credential GitHub : l'upstream repondrait 401 de toute
    // facon ; OAuth/discovery restent servies. L'upstream n'est jamais contacte.
    if state.upstream_token.is_none() {
        return json_response(
            StatusCode::OK,
            error::jsonrpc_error(
                None,
                codes::APP,
                "credential GitHub non configure cote passerelle (fail-closed)",
            ),
        );
    }

    // Coherence `_meta.protocolVersion` (strippee si non supportee par le Go).
    let (stripped, _) = compat::strip_unsupported_meta(body_bytes);
    body_bytes = stripped;

    forward(
        &state,
        &method,
        &path,
        query.as_deref(),
        &parts.headers,
        body_bytes,
        &scopes,
    )
    .await
}

async fn forward(
    state: &AppState,
    method: &Method,
    path: &str,
    query: Option<&str>,
    headers: &axum::http::HeaderMap,
    body: Option<Vec<u8>>,
    scopes: &HashSet<String>,
) -> Response {
    use mcp_http::proxy as hp;

    let mut outgoing = hp::forward_request_headers(headers);
    // Compat Go v1.12.0 : Accept dual + coherence de version au-dela du
    // rewrite framework (remplacement par le corps, sinon retrait).
    compat::normalize_accept(&mut outgoing);
    compat::fix_version_header(&mut outgoing, body.as_deref());
    let url = match query {
        Some(q) if !q.is_empty() => format!("{}{}?{q}", state.upstream, path),
        _ => format!("{}{}", state.upstream, path),
    };
    let mut builder = state.client.request(method.clone(), url);
    for (name, value) in outgoing.iter() {
        builder = builder.header(name, value);
    }
    // PAT interne (jamais journalise) ; l'`Authorization` client n'est jamais
    // retransmise (hors allowlist du framework).
    if let Some(tok) = &state.upstream_token {
        builder = builder.bearer_auth(&tok.0);
    }
    if *method == Method::POST {
        builder = builder.timeout(Duration::from_secs(mcp_http::hardening::PROXY_TIMEOUT_SECS));
    }
    // Corps de requete conserve pour la normalisation fichier (POST).
    let request_body = body.clone();
    if let Some(b) = body {
        builder = builder.body(b);
    }
    let upstream = match builder.send().await {
        Ok(r) => r,
        Err(_) => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                error::bad_gateway_body("HttpError"),
            );
        }
    };
    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let out_headers = hp::forward_response_headers(upstream.headers());

    if *method == Method::GET {
        let stream = upstream.bytes_stream();
        let mut builder = Response::builder().status(status);
        for (name, value) in out_headers.iter() {
            builder = builder.header(name, value);
        }
        return builder
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response());
    }

    let content_type = out_headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mut bytes = match upstream.bytes().await {
        Ok(b) => b.to_vec(),
        Err(_) => {
            return json_response(
                StatusCode::BAD_GATEWAY,
                error::bad_gateway_body("HttpError"),
            );
        }
    };
    if *method == Method::POST {
        // Ordre Python : normalisation fichier PUIS filtrage tools/list.
        if let Some(norm) =
            file_norm::normalize_file_response(request_body.as_deref(), &bytes, &content_type)
        {
            bytes = norm;
        }
        let visibles = state.policy.visibles(scopes);
        bytes = hp::filter_tools_list(&bytes, &content_type, &visibles);
    }
    let mut builder = Response::builder().status(status);
    for (name, value) in out_headers.iter() {
        builder = builder.header(name, value);
    }
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}
