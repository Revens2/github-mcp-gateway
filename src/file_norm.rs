//! Normalisation des reponses `get_file_contents` (anti-materialisation ChatGPT).
//!
//! Transcription exacte de `github_gateway/lecture_fichier.py` (prouve sur
//! reponse brute upstream v1.12.0) : pour un fichier texte l'upstream renvoie
//! un bloc `text` + un bloc `resource` (EmbeddedResource materialise en piece
//! jointe) ; les gros fichiers (`resource_link`) et binaires (`blob`) suivent
//! le meme sort. Seul `result.content` des reponses a un `tools/call` de
//! `get_file_contents` est touche ; tout le reste passe a l'octet pres.

use serde_json::{json, Map, Value};

/// Seul outil reecrit : la lecture de fichier.
pub const FILE_TOOL: &str = "get_file_contents";

/// Blocs MCP qui declenchent une materialisation cote ChatGPT Web.
fn is_file_block(t: &str) -> bool {
    matches!(t, "resource" | "resource_link")
}

fn chemin_depuis_uri(uri: Option<&Value>) -> String {
    let s = match uri.and_then(Value::as_str) {
        Some(s) if !s.is_empty() => s,
        _ => return String::new(),
    };
    let marqueur = "/contents/";
    match s.find(marqueur) {
        Some(i) => s[i + marqueur.len()..].to_string(),
        None => String::new(),
    }
}

fn convertir_resource(message: &str, resource: Option<&Value>) -> Option<Value> {
    let r = resource?.as_object()?;
    let chemin = chemin_depuis_uri(r.get("uri"));
    let mime = r
        .get("mimeType")
        .and_then(Value::as_str)
        .filter(|m| !m.is_empty())
        .unwrap_or("type inconnu");
    if let Some(texte) = r.get("text").and_then(Value::as_str) {
        let mut entete = message.to_string();
        if !chemin.is_empty() {
            if !entete.is_empty() {
                entete.push('\n');
            }
            entete.push_str(&format!("Fichier : {chemin} | MIME : {mime}"));
        }
        let sep = if entete.is_empty() { "" } else { "\n\n" };
        return Some(json!({"type": "text", "text": format!("{entete}{sep}{texte}")}));
    }
    if r.get("blob").and_then(Value::as_str).is_some() {
        let entete = if message.is_empty() {
            "Fichier binaire recu.".to_string()
        } else {
            message.to_string()
        };
        let ou = if chemin.is_empty() {
            "chemin inconnu".to_string()
        } else {
            chemin
        };
        return Some(json!({"type": "text", "text": format!(
            "{entete}\nFichier binaire : {ou} | MIME : {mime} — contenu non renvoye en ligne (aucune piece jointe)."
        )}));
    }
    None
}

fn convertir_lien(message: &str, lien: Option<&Value>) -> Value {
    if !message.is_empty() {
        return json!({"type": "text", "text": message});
    }
    let nom = lien
        .and_then(|l| l.get("name"))
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
        .unwrap_or("fichier");
    json!({"type": "text", "text": format!(
        "Fichier {nom} trop volumineux pour un affichage en ligne — aucune piece jointe renvoyee."
    )})
}

/// Reecrit `payload["result"]["content"]` en place. `true` si reecriture.
fn transformer_payload(payload: &mut Map<String, Value>) -> bool {
    let contenu = match payload
        .get_mut("result")
        .and_then(|r| r.as_object_mut())
        .and_then(|r| r.get_mut("content"))
        .and_then(|c| c.as_array())
    {
        Some(c) if !c.is_empty() => c,
        _ => return false,
    };
    if !contenu.iter().any(|b| {
        b.as_object()
            .and_then(|o| o.get("type"))
            .and_then(Value::as_str)
            .is_some_and(is_file_block)
    }) {
        return false;
    }
    let message = contenu
        .iter()
        .filter_map(|b| {
            let o = b.as_object()?;
            if o.get("type")?.as_str()? != "text" {
                return None;
            }
            o.get("text")?.as_str()
        })
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let mut nouveaux = Vec::with_capacity(contenu.len());
    for bloc in contenu.iter() {
        let o = match bloc.as_object() {
            None => {
                nouveaux.push(bloc.clone());
                continue;
            }
            Some(o) => o,
        };
        match o.get("type").and_then(Value::as_str) {
            Some("text") => continue,
            Some("resource") => match convertir_resource(&message, o.get("resource")) {
                Some(c) => nouveaux.push(c),
                None => nouveaux.push(json!({"type": "text", "text": format!(
                    "{}{}Ressource de forme inattendue non renvoyee en ligne (aucune piece jointe).",
                    message,
                    if message.is_empty() { "" } else { "\n" }
                )})),
            },
            Some("resource_link") => nouveaux.push(convertir_lien(&message, Some(bloc))),
            _ => nouveaux.push(bloc.clone()),
        }
    }
    if let Some(r) = payload.get_mut("result").and_then(|r| r.as_object_mut()) {
        r.insert("content".to_string(), Value::Array(nouveaux));
    }
    true
}

fn normaliser_json(corps: &[u8]) -> Option<Vec<u8>> {
    let mut v: Value = serde_json::from_slice(corps).ok()?;
    v.as_object()?;
    let changed = v.as_object_mut().is_some_and(transformer_payload);
    if !changed {
        return None;
    }
    serde_json::to_vec(&v).ok()
}

fn normaliser_sse(corps: &[u8]) -> Option<Vec<u8>> {
    let mut modifie = false;
    let mut lignes: Vec<Vec<u8>> = Vec::new();
    for ligne in corps.split(|b| *b == b'\n') {
        if !ligne.starts_with(b"data: ") {
            lignes.push(ligne.to_vec());
            continue;
        }
        let brut = &ligne[6..];
        if brut.iter().all(|b| b.is_ascii_whitespace()) {
            lignes.push(ligne.to_vec());
            continue;
        }
        let mut v: Value = match serde_json::from_slice(brut) {
            Ok(v) => v,
            Err(_) => {
                lignes.push(ligne.to_vec());
                continue;
            }
        };
        let changed = v.as_object_mut().is_some_and(transformer_payload);
        if !changed {
            lignes.push(ligne.to_vec());
            continue;
        }
        match serde_json::to_vec(&v) {
            Ok(out) => {
                let mut l = b"data: ".to_vec();
                l.extend_from_slice(&out);
                lignes.push(l);
                modifie = true;
            }
            Err(_) => lignes.push(ligne.to_vec()),
        }
    }
    if !modifie {
        return None;
    }
    Some(lignes.join(&b'\n'))
}

/// Normalise une reponse `tools/call get_file_contents` (JSON ou SSE).
/// Tout autre cas : `None` (= octets d'origine INCHANGES).
pub fn normalize_file_response(
    request_body: Option<&[u8]>,
    response_body: &[u8],
    content_type: &str,
) -> Option<Vec<u8>> {
    if crate::compat::body_tool_name(request_body) != Some(FILE_TOOL.to_string()) {
        return None;
    }
    if content_type.to_lowercase().contains("text/event-stream") {
        return normaliser_sse(response_body);
    }
    normaliser_json(response_body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_file_contents"}}"#
            .to_vec()
    }

    #[test]
    fn autre_outil_intact() {
        let req = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_me"}}"#
            .to_vec();
        let resp = br#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"x"}]}}"#;
        assert!(normalize_file_response(Some(&req), resp, "application/json").is_none());
    }

    #[test]
    fn ressource_texte_aplatie_sans_resource() {
        let resp = br#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok (SHA: abc)"},{"type":"resource","resource":{"uri":"repo://o/r/contents/a/b.txt","mimeType":"text/plain; charset=utf-8","text":"CONTENU"}}]}}"#;
        let out = normalize_file_response(Some(&req()), resp, "application/json").unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        let c = v["result"]["content"].as_array().unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0]["type"], "text");
        let t = c[0]["text"].as_str().unwrap();
        assert!(t.contains("CONTENU"), "{t}");
        assert!(t.contains("a/b.txt"), "{t}");
        assert!(!t.contains("repo://"), "{t}");
    }

    #[test]
    fn blob_jamais_reinjecte() {
        let resp = br#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"resource","resource":{"uri":"repo://o/r/contents/a.bin","mimeType":"application/octet-stream","blob":"QUJD"}}]}}"#;
        let out = normalize_file_response(Some(&req()), resp, "application/json").unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        let t = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!t.contains("QUJD"), "{t}");
        assert!(t.contains("binaire"), "{t}");
    }

    #[test]
    fn lien_ressource_sans_lien() {
        let resp = br#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"gros"},{"type":"resource_link","uri":"repo://o/r/contents/big.bin","name":"big.bin"}]}}"#;
        let out = normalize_file_response(Some(&req()), resp, "application/json").unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        let c = v["result"]["content"].as_array().unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0]["type"], "text");
    }

    #[test]
    fn erreur_upstream_intacte() {
        let resp = br#"{"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"x"}}"#;
        assert!(normalize_file_response(Some(&req()), resp, "application/json").is_none());
    }
}
