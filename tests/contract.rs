//! Contrat github-gateway-rs : politique 59R/35W fail-closed + gateway HTTP.
//!
//! Preuves exigibles du lot 3 :
//! * les 59 outils de lecture sont autorises en lecture seule ;
//! * les 35 mutateurs exigent la portee ecriture (`delete_repository` inclus,
//!   gate MRTR cote upstream, comme le Python) ;
//! * l'inconnu est refuse meme avec toutes les portees (fail-closed) ;
//! * `visibles` : 59 en lecture, 94 en lecture+ecriture, 0 sans lecture ;
//! * la gateway exige un Bearer sur `/mcp` (401 + `www-authenticate`), sert
//!   `/health` au format Python (`upstream_auth`), la PRM exacte ;
//! * le relais injecte le PAT upstream (jamais le Bearer client) ;
//! * sans PAT : refus local -32000 AVANT tout envoi (l'upstream n'est jamais
//!   contacte) ;
//! * `get_file_contents` normalise en texte direct (pas de resource/blob/lien).

use std::collections::HashSet;

use github_gateway_rs::{
    file_norm, policy, OUTILS_ECRITURE, OUTILS_LECTURE, READ_SCOPE, WRITE_SCOPE,
};
use mcp_auth::policy::{ToolClass, ToolPolicy};
use mcp_gateway::testkit::compare_tools_list;

fn scopes(s: &[&str]) -> HashSet<String> {
    s.iter().map(|x| x.to_string()).collect()
}

#[test]
fn tailles_politique_59r_35w() {
    assert_eq!(OUTILS_LECTURE.len(), 59, "regression table lecture");
    assert_eq!(OUTILS_ECRITURE.len(), 35, "regression table ecriture");
    assert_eq!(OUTILS_LECTURE.len() + OUTILS_ECRITURE.len(), 94);
}

#[test]
fn lectures_autorisees_en_lecture_seule() {
    let p = policy();
    for tool in OUTILS_LECTURE {
        assert_eq!(p.classify(tool), ToolClass::Read, "outil {tool}");
        assert!(
            p.autoriser_call(tool, &scopes(&[READ_SCOPE])).is_none(),
            "outil {tool} refuse a tort"
        );
    }
}

#[test]
fn ecritures_exigent_la_portee_ecriture() {
    let p = policy();
    for tool in OUTILS_ECRITURE {
        assert_eq!(p.classify(tool), ToolClass::Write, "outil {tool}");
        assert!(
            p.autoriser_call(tool, &scopes(&[READ_SCOPE])).is_some(),
            "outil {tool} autorise a tort en lecture"
        );
        assert!(
            p.autoriser_call(tool, &scopes(&[READ_SCOPE, WRITE_SCOPE]))
                .is_none(),
            "outil {tool} refuse a tort en ecriture"
        );
    }
}

#[test]
fn delete_repository_ecriture_pas_admin() {
    // Parite Python : aucun outil bloque en admin, le gate MRTR est upstream.
    let p = policy();
    assert_eq!(p.classify("delete_repository"), ToolClass::Write);
    assert!(p
        .autoriser_call("delete_repository", &scopes(&[READ_SCOPE, WRITE_SCOPE]))
        .is_none());
}

#[test]
fn inconnu_refuse_fail_closed_meme_full_scopes() {
    let p = policy();
    assert_eq!(p.classify("drop_database"), ToolClass::Unknown);
    assert!(p
        .autoriser_call("drop_database", &scopes(&[READ_SCOPE, WRITE_SCOPE]))
        .is_some());
    assert!(p
        .autoriser_call("outil-futur-upstream", &scopes(&[READ_SCOPE, WRITE_SCOPE]))
        .is_some());
}

#[test]
fn visibles_59_94_zero() {
    let p = policy();
    assert_eq!(p.visibles(&scopes(&[READ_SCOPE])).len(), 59);
    assert_eq!(p.visibles(&scopes(&[READ_SCOPE, WRITE_SCOPE])).len(), 94);
    assert!(p.visibles(&scopes(&[])).is_empty());
    // Semantique framework (lots 1-2) : ecriture implique lecture pour
    // `visibles`/`autoriser_call`. Inatteignable en pratique : le middleware
    // exige la portee lecture pour atteindre `/mcp`, et tous les jetons emis
    // la portent. Divergence assumee, sans effet sur le diff contrat.
    assert_eq!(p.visibles(&scopes(&[WRITE_SCOPE])).len(), 94);
}

#[test]
fn testkit_releve_perte_outil() {
    let ancien = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": [
            {"name": "get_me", "description": "d", "inputSchema": {"type": "object"}},
            {"name": "create_gist", "description": "d", "inputSchema": {"type": "object"}},
        ]}
    });
    let mut nouveau = ancien.clone();
    let outils = nouveau["result"]["tools"].as_array_mut().unwrap();
    outils.retain(|t| t["name"] != "create_gist");
    let diffs = compare_tools_list(&ancien, &nouveau);
    assert!(
        diffs
            .iter()
            .any(|d| d.contains("outil perdu : create_gist")),
        "{diffs:?}"
    );
}

fn oauth_cfg() -> mcp_auth::oauth::OAuthConfig {
    mcp_auth::oauth::OAuthConfig {
        issuer: "https://mymcps.duckdns.org/oauth/github".to_string(),
        resource_url: github_gateway_rs::RESOURCE_URL.to_string(),
        resource_name: github_gateway_rs::RESOURCE_NAME.to_string(),
        default_scope: READ_SCOPE.to_string(),
        valid_scopes: vec![READ_SCOPE.to_string(), WRITE_SCOPE.to_string()],
        extra_submit_scopes: vec![WRITE_SCOPE.to_string()],
        consent_hash: String::new(),
        static_client_id: "github-mcp-cli-statique".to_string(),
    }
}

fn gateway_test(pat: bool) -> axum::Router {
    use github_gateway_rs::{build_router, ServiceConfig, UpstreamToken};

    build_router(ServiceConfig {
        upstream: "http://127.0.0.1:9".to_string(),
        upstream_token: if pat {
            Some(UpstreamToken::new("p".repeat(32)))
        } else {
            None
        },
        static_token: "x".repeat(32),
        static_token_scopes: vec![READ_SCOPE.to_string(), WRITE_SCOPE.to_string()],
        oauth: oauth_cfg(),
        max_body_bytes: 1024 * 1024,
    })
    .expect("gateway de test")
}

#[tokio::test]
async fn mcp_sans_bearer_401_fail_closed() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let app = gateway_test(true);
    let res = app
        .oneshot(Request::post("/mcp").body(Body::from("{}")).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let challenge = res.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(challenge.contains("resource_metadata"), "{challenge}");
    assert!(
        challenge.contains("oauth-protected-resource/github/mcp"),
        "{challenge}"
    );
}

#[tokio::test]
async fn health_format_python_avec_upstream_auth() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    for (pat, attendu) in [(true, "configure"), (false, "missing")] {
        let app = gateway_test(pat);
        let res = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["service"], "github-gateway-rs");
        assert_eq!(v["mcp"], "/mcp");
        assert_eq!(v["upstream_auth"], attendu);
    }
}

#[tokio::test]
async fn prm_alias_resource_exacte() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let app = gateway_test(true);
    let res = app
        .oneshot(
            Request::get(github_gateway_rs::PRM_ALIAS)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 8192).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["resource"], github_gateway_rs::RESOURCE_URL);
    assert_eq!(
        v["authorization_servers"],
        serde_json::json!(["https://mymcps.duckdns.org/oauth/github"])
    );
    assert_eq!(v["resource_name"], "GitHub MCP (passerelle)");
}

/// Sans PAT : refus local -32000 AVANT tout envoi (upstream injoignable de
/// toute facon ici, mais le message doit etre le fail-closed, pas du 502).
#[tokio::test]
async fn sans_pat_refus_local_avant_upstream() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let app = gateway_test(false);
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let res = app
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {}", "x".repeat(32)))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["error"]["code"], -32000);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("non configure"),
        "{v}"
    );
}

/// Le relais injecte le PAT upstream (jamais le Bearer client) : le mock
/// exige `Authorization: Bearer <pat>` puis repond `tools/list` filtrable.
#[tokio::test]
async fn relais_injecte_pat_upstream() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let mock = axum::Router::new().route(
        "/mcp",
        axum::routing::post(|req: axum::extract::Request| async move {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            assert_eq!(auth, format!("Bearer {}", "p".repeat(32)));
            assert!(!auth.contains(&"x".repeat(8)));
            (
                StatusCode::OK,
                [("content-type", "application/json")],
                r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_me","description":"d","inputSchema":{"type":"object"}},{"name":"outil-fantome","description":"d","inputSchema":{"type":"object"}}]}}"#,
            )
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });

    use github_gateway_rs::{build_router, ServiceConfig, UpstreamToken};
    let app = build_router(ServiceConfig {
        upstream: format!("http://127.0.0.1:{}", addr.port()),
        upstream_token: Some(UpstreamToken::new("p".repeat(32))),
        static_token: "x".repeat(32),
        static_token_scopes: vec![READ_SCOPE.to_string(), WRITE_SCOPE.to_string()],
        oauth: oauth_cfg(),
        max_body_bytes: 1024 * 1024,
    })
    .unwrap();

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
    let res = app
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {}", "x".repeat(32)))
                .header("content-type", "application/json")
                .header("accept", "application/json, text/event-stream")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 8192).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let outils = v["result"]["tools"].as_array().unwrap();
    // `outil-fantome` (inconnu de la table) est filtre de tools/list.
    assert_eq!(outils.len(), 1);
    assert_eq!(outils[0]["name"], "get_me");
}

#[tokio::test]
async fn ecriture_sans_portee_refusee_avant_upstream() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use github_gateway_rs::{build_router, ServiceConfig, UpstreamToken};
    // Jeton client lecture seule : l'ecriture doit etre refusee en local.
    let app = build_router(ServiceConfig {
        upstream: "http://127.0.0.1:9".to_string(),
        upstream_token: Some(UpstreamToken::new("p".repeat(32))),
        static_token: "y".repeat(32),
        static_token_scopes: vec![READ_SCOPE.to_string()],
        oauth: oauth_cfg(),
        max_body_bytes: 1024 * 1024,
    })
    .unwrap();
    let body = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_gist","arguments":{}}}"#;
    let res = app
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {}", "y".repeat(32)))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["id"], 7);
    assert_eq!(v["error"]["code"], -32000);
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("github:ecriture"),
        "{v}"
    );
}

#[tokio::test]
async fn appel_outil_inconnu_refuse_avant_upstream() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let app = gateway_test(true);
    let body =
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"drop_database"}}"#;
    let res = app
        .oneshot(
            Request::post("/mcp")
                .header("authorization", format!("Bearer {}", "x".repeat(32)))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["id"], 7);
    assert_eq!(v["error"]["code"], -32000);
}

#[test]
fn fichier_texte_normalise_pas_de_resource() {
    let req =
        br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_file_contents"}}"#;
    let resp = br#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"},{"type":"resource","resource":{"uri":"repo://o/r/contents/f.txt","mimeType":"text/plain","text":"DATA"}}]}}"#;
    let out = file_norm::normalize_file_response(Some(req), resp, "application/json").unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let c = v["result"]["content"].as_array().unwrap();
    assert_eq!(c.len(), 1);
    assert!(c[0]["text"].as_str().unwrap().contains("DATA"));
}
