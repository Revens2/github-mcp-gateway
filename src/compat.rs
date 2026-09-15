//! Compatibilite stricte avec l'upstream Go fige (`github-mcp-server` v1.12.0).
//!
//! Transcription de `github_gateway/upstream.py` (metier local au depot,
//! jamais dans le framework) :
//! * `Accept` normalise vers `application/json, text/event-stream` des qu'un
//!   des deux manque (le Go repond 400 sinon ; constate avec ChatGPT) ;
//! * version d'en-tete `mcp-protocol-version` non supportee : remplacee par
//!   celle du corps `initialize` quand elle est supportee, sinon retiree
//!   (le corps parle alors seul) ;
//! * cle `_meta["io.modelcontextprotocol/protocolVersion"]` non supportee
//!   retiree du corps (sinon -32602 persistant apres rabais de l'en-tete).

use axum::http::HeaderMap;
use serde_json::Value;

/// Versions acceptees par l'upstream officiel v1.12.0 (400 au-dela).
pub const SUPPORTED_VERSIONS: &[&str] = &["2025-03-26", "2025-06-18", "2025-11-25"];

/// Cle `_meta` qui porte la version de protocole cote client recent.
pub const META_VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";

/// `protocolVersion` du corps d'un `initialize`, ou `None` (autre methode).
pub fn body_initialize_version(body: Option<&[u8]>) -> Option<String> {
    let v: Value = serde_json::from_slice(body?).ok()?;
    if v.get("method")?.as_str()? != "initialize" {
        return None;
    }
    v.get("params")?
        .get("protocolVersion")?
        .as_str()
        .map(str::to_string)
}

/// Nom de methode JSON-RPC du corps, ou `None`.
pub fn body_rpc_method(body: Option<&[u8]>) -> Option<String> {
    let v: Value = serde_json::from_slice(body?).ok()?;
    v.get("method")?.as_str().map(str::to_string)
}

/// Nom d'outil d'un corps `tools/call`, ou `None` (autre methode).
pub fn body_tool_name(body: Option<&[u8]>) -> Option<String> {
    let v: Value = serde_json::from_slice(body?).ok()?;
    if v.get("method")?.as_str()? != "tools/call" {
        return None;
    }
    v.get("params")?.get("name")?.as_str().map(str::to_string)
}

/// Normalise `Accept` vers les deux enveloppes exigees par le Go.
/// Retourne `true` si l'en-tete a ete (re)pose.
pub fn normalize_accept(headers: &mut HeaderMap) -> bool {
    const BOTH: &str = "application/json, text/event-stream";
    let needs = match headers.get("accept").and_then(|v| v.to_str().ok()) {
        None => true,
        Some(a) => {
            let low = a.to_lowercase();
            !(low.contains("application/json") && low.contains("text/event-stream"))
        }
    };
    if needs {
        if let Ok(v) = BOTH.parse() {
            headers.insert("accept", v);
            return true;
        }
    }
    false
}

/// Coherence de version cote en-tete (miroir de `_entetes_upstream`).
/// Version non supportee : remplacee par celle du corps si supportee,
/// sinon retiree. Retourne `(touchee, retiree)`.
pub fn fix_version_header(headers: &mut HeaderMap, body: Option<&[u8]>) -> (bool, bool) {
    let current = match headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
    {
        None => return (false, false),
        Some(v) => v.trim().to_string(),
    };
    if SUPPORTED_VERSIONS.contains(&current.as_str()) {
        return (false, false);
    }
    match body_initialize_version(body) {
        Some(v) if SUPPORTED_VERSIONS.contains(&v.as_str()) => {
            if let Ok(hv) = v.parse() {
                headers.insert("mcp-protocol-version", hv);
                return (true, false);
            }
            (false, false)
        }
        _ => {
            headers.remove("mcp-protocol-version");
            (true, true)
        }
    }
}

/// Retire la cle `_meta.protocolVersion` non supportee du corps JSON.
/// Retourne `(corps, strippe?)`, octets d'origine si rien ne change.
pub fn strip_unsupported_meta(body: Option<Vec<u8>>) -> (Option<Vec<u8>>, bool) {
    let bytes = match body {
        None => return (None, false),
        Some(b) if b.is_empty() => return (Some(b), false),
        Some(b) => b,
    };
    let mut v: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return (Some(bytes), false),
    };
    let strip = (|| {
        let params = v.get_mut("params")?.as_object_mut()?;
        let meta = params.get_mut("_meta")?.as_object_mut()?;
        let cur = meta.get(META_VERSION_KEY)?.as_str()?;
        if SUPPORTED_VERSIONS.contains(&cur) {
            return None;
        }
        meta.remove(META_VERSION_KEY);
        if meta.is_empty() {
            params.remove("_meta");
        }
        Some(())
    })();
    if strip.is_none() {
        return (Some(bytes), false);
    }
    match serde_json::to_vec(&v) {
        Ok(out) => (Some(out), true),
        Err(_) => (Some(bytes), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_complete_laisse_intact() {
        let mut h = HeaderMap::new();
        h.insert(
            "accept",
            "application/json, text/event-stream".parse().unwrap(),
        );
        assert!(!normalize_accept(&mut h));
    }

    #[test]
    fn accept_partiel_normalise() {
        let mut h = HeaderMap::new();
        h.insert("accept", "application/json".parse().unwrap());
        assert!(normalize_accept(&mut h));
        assert_eq!(
            h["accept"].to_str().unwrap(),
            "application/json, text/event-stream"
        );
    }

    #[test]
    fn version_supportee_intacte() {
        let mut h = HeaderMap::new();
        h.insert("mcp-protocol-version", "2025-11-25".parse().unwrap());
        assert_eq!(fix_version_header(&mut h, None), (false, false));
    }

    #[test]
    fn version_inconnue_remplacee_par_corps() {
        let mut h = HeaderMap::new();
        h.insert("mcp-protocol-version", "2026-07-28".parse().unwrap());
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
        assert_eq!(fix_version_header(&mut h, Some(body)), (true, false));
        assert_eq!(h["mcp-protocol-version"].to_str().unwrap(), "2025-06-18");
    }

    #[test]
    fn version_inconnue_sans_corps_retiree() {
        let mut h = HeaderMap::new();
        h.insert("mcp-protocol-version", "2099-01-01".parse().unwrap());
        assert_eq!(fix_version_header(&mut h, None), (true, true));
        assert!(!h.contains_key("mcp-protocol-version"));
    }

    #[test]
    fn meta_non_supportee_strippee() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","autre":1}}}"#.to_vec();
        let (out, stripped) = strip_unsupported_meta(Some(body));
        assert!(stripped);
        let v: Value = serde_json::from_slice(&out.unwrap()).unwrap();
        assert!(v["params"]["_meta"].get(META_VERSION_KEY).is_none());
        assert_eq!(v["params"]["_meta"]["autre"], 1);
    }

    #[test]
    fn meta_supportee_intacte() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#.to_vec();
        let (_, stripped) = strip_unsupported_meta(Some(body));
        assert!(!stripped);
    }
}
