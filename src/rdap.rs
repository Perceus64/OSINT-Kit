//! RDAP (the structured successor to WHOIS) summary.

use serde::Serialize;
use serde_json::Value;

use crate::util::iso_to_days;

#[derive(Serialize, Debug, Default)]
pub struct RdapReport {
    pub domain: String,
    pub registrar: Option<String>,
    pub registrar_iana_id: Option<String>,
    pub registered: Option<String>,
    pub expires: Option<String>,
    pub last_changed: Option<String>,
    pub age_days: Option<i64>,
    pub days_to_expiry: Option<i64>,
    pub status: Vec<String>,
    pub nameservers: Vec<String>,
    pub dnssec_signed: Option<bool>,
    pub abuse_contact: Option<String>,
    pub notes: Vec<String>,
}

fn s(v: &Value) -> Option<String> {
    v.as_str().map(|x| x.to_string())
}

/// Pull the "fn" (formatted name) or a given property out of a jCard.
fn vcard_prop(entity: &Value, prop: &str) -> Option<String> {
    let arr = entity.get("vcardArray")?.get(1)?.as_array()?;
    for item in arr {
        let item = item.as_array()?;
        if item.first()?.as_str()? == prop {
            let v = item.get(3)?;
            return match v {
                Value::String(x) => Some(x.clone()),
                Value::Array(a) => Some(
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(" "),
                ),
                _ => None,
            };
        }
    }
    None
}

fn has_role(entity: &Value, role: &str) -> bool {
    entity
        .get("roles")
        .and_then(|r| r.as_array())
        .map(|r| r.iter().any(|x| x.as_str() == Some(role)))
        .unwrap_or(false)
}

pub fn analyze(json: &str, now_ms: f64) -> Result<RdapReport, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("bad RDAP response: {e}"))?;
    if v.get("errorCode").is_some() {
        let t = v
            .get("title")
            .and_then(s)
            .unwrap_or_else(|| "lookup failed".into());
        return Err(format!("RDAP: {t}"));
    }
    let mut r = RdapReport {
        domain: v
            .get("ldhName")
            .and_then(s)
            .unwrap_or_default()
            .to_ascii_lowercase(),
        ..Default::default()
    };

    if let Some(events) = v.get("events").and_then(|e| e.as_array()) {
        for e in events {
            let action = e.get("eventAction").and_then(|x| x.as_str()).unwrap_or("");
            let date = e.get("eventDate").and_then(s);
            match action {
                "registration" => r.registered = date,
                "expiration" => r.expires = date,
                "last changed" => r.last_changed = date,
                _ => {}
            }
        }
    }

    let today = (now_ms / 86_400_000.0).floor() as i64;
    r.age_days = r
        .registered
        .as_deref()
        .and_then(iso_to_days)
        .map(|d| today - d);
    r.days_to_expiry = r
        .expires
        .as_deref()
        .and_then(iso_to_days)
        .map(|d| d - today);

    if let Some(st) = v.get("status").and_then(|x| x.as_array()) {
        r.status = st.iter().filter_map(s).collect();
    }
    if let Some(ns) = v.get("nameservers").and_then(|x| x.as_array()) {
        r.nameservers = ns
            .iter()
            .filter_map(|n| n.get("ldhName").and_then(s))
            .map(|n| n.to_ascii_lowercase())
            .collect();
    }
    r.dnssec_signed = v
        .get("secureDNS")
        .and_then(|x| x.get("delegationSigned"))
        .and_then(|x| x.as_bool());

    if let Some(entities) = v.get("entities").and_then(|x| x.as_array()) {
        for e in entities {
            if has_role(e, "registrar") {
                r.registrar = vcard_prop(e, "fn");
                r.registrar_iana_id = e
                    .get("publicIds")
                    .and_then(|p| p.as_array())
                    .and_then(|p| p.iter().find_map(|x| x.get("identifier").and_then(s)));
                // Abuse contact is usually nested under the registrar.
                if let Some(sub) = e.get("entities").and_then(|x| x.as_array()) {
                    for se in sub {
                        if has_role(se, "abuse") {
                            r.abuse_contact =
                                vcard_prop(se, "email").or_else(|| vcard_prop(se, "tel"));
                        }
                    }
                }
            }
        }
    }

    if let Some(age) = r.age_days {
        if age < 30 {
            r.notes.push(format!(
                "Newly registered ({age} days old) — a common trait of phishing domains."
            ));
        } else if age < 180 {
            r.notes
                .push(format!("Fairly young domain ({age} days old)."));
        }
    }
    if let Some(d) = r.days_to_expiry {
        if d < 0 {
            r.notes.push("Registration has expired.".into());
        } else if d < 30 {
            r.notes.push(format!("Expires in {d} days."));
        }
    }
    let locks = r.status.iter().filter(|s| s.contains("prohibited")).count();
    if locks == 0 && !r.status.is_empty() {
        r.notes
            .push("No transfer/update locks set — the domain is easier to hijack.".into());
    }
    if r.status.iter().any(|s| s.contains("hold")) {
        r.notes
            .push("Domain is on hold (often suspended by the registry or registrar).".into());
    }

    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rdap() {
        let j = serde_json::json!({
            "ldhName": "EXAMPLE.COM",
            "events": [
                {"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
                {"eventAction":"expiration","eventDate":"2027-08-13T04:00:00Z"}
            ],
            "status": ["client delete prohibited", "client transfer prohibited"],
            "nameservers": [{"ldhName":"A.IANA-SERVERS.NET"}],
            "secureDNS": {"delegationSigned": true},
            "entities": [{
                "roles":["registrar"],
                "publicIds":[{"type":"IANA Registrar ID","identifier":"376"}],
                "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]],
                "entities":[{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@iana.org"]]]}]
            }]
        })
        .to_string();
        // 2026-10-15
        let now = crate::util::days_from_civil(2026, 10, 15) as f64 * 86_400_000.0;
        let r = analyze(&j, now).unwrap();
        assert_eq!(r.domain, "example.com");
        assert_eq!(
            r.registrar.as_deref(),
            Some("RESERVED-Internet Assigned Numbers Authority")
        );
        assert_eq!(r.registrar_iana_id.as_deref(), Some("376"));
        assert_eq!(r.abuse_contact.as_deref(), Some("abuse@iana.org"));
        assert_eq!(r.nameservers, vec!["a.iana-servers.net"]);
        assert_eq!(r.dnssec_signed, Some(true));
        assert!(r.age_days.unwrap() > 11_000);
        assert!(r.notes.is_empty());
    }

    #[test]
    fn rdap_error() {
        assert!(analyze(r#"{"errorCode":404,"title":"Not Found"}"#, 0.0).is_err());
    }
}
