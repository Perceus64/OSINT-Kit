//! Certificate-transparency subdomain inventory from crt.sh JSON.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct CrtEntry {
    #[serde(default)]
    name_value: String,
    #[serde(default)]
    common_name: String,
    #[serde(default)]
    issuer_name: String,
    #[serde(default)]
    not_before: String,
    #[serde(default)]
    not_after: String,
}

#[derive(Serialize, Debug)]
pub struct Subdomain {
    pub name: String,
    pub wildcard: bool,
    pub certs: u32,
    pub first_seen: String,
    pub last_seen: String,
    pub latest_expiry: String,
}

#[derive(Serialize, Debug)]
pub struct Issuer {
    pub name: String,
    pub certs: u32,
}

#[derive(Serialize, Debug)]
pub struct CertReport {
    pub total_certs: usize,
    pub subdomains: Vec<Subdomain>,
    pub issuers: Vec<Issuer>,
    pub interesting: Vec<String>,
}

/// Subdomain labels that often point at admin panels, staging or internal
/// systems — worth a closer look during an assessment of your own estate.
const INTERESTING: &[&str] = &[
    "admin",
    "dev",
    "staging",
    "stage",
    "test",
    "uat",
    "qa",
    "beta",
    "internal",
    "intranet",
    "vpn",
    "remote",
    "jenkins",
    "gitlab",
    "git",
    "jira",
    "confluence",
    "grafana",
    "kibana",
    "portal",
    "sso",
    "login",
    "auth",
    "api",
    "backup",
    "old",
    "legacy",
    "db",
    "mail",
    "webmail",
    "owa",
    "citrix",
    "rdp",
    "ftp",
    "sftp",
    "phpmyadmin",
    "cpanel",
    "monitor",
    "status",
    "demo",
];

fn issuer_org(issuer: &str) -> String {
    // "C=US, O=Let's Encrypt, CN=R3" -> "Let's Encrypt"
    issuer
        .split(", ")
        .find_map(|p| p.strip_prefix("O="))
        .map(|s| s.trim_matches('"').to_string())
        .unwrap_or_else(|| issuer.to_string())
}

pub fn analyze(json: &str, domain: &str) -> Result<CertReport, String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let entries: Vec<CrtEntry> =
        serde_json::from_str(json).map_err(|e| format!("bad crt.sh response: {e}"))?;

    let mut subs: BTreeMap<String, Subdomain> = BTreeMap::new();
    let mut issuers: BTreeMap<String, u32> = BTreeMap::new();

    for e in &entries {
        *issuers.entry(issuer_org(&e.issuer_name)).or_default() += 1;
        let mut names: Vec<&str> = e.name_value.split('\n').collect();
        names.push(&e.common_name);
        let mut names: Vec<String> = names
            .into_iter()
            .map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|n| !n.is_empty() && !n.contains(' ') && !n.contains('@'))
            .collect();
        names.sort();
        names.dedup();
        for raw in names {
            let wildcard = raw.starts_with("*.");
            let name = raw.trim_start_matches("*.").to_string();
            if !(name == domain || name.ends_with(&format!(".{domain}"))) {
                continue;
            }
            let nb = e.not_before.get(0..10).unwrap_or("").to_string();
            let na = e.not_after.get(0..10).unwrap_or("").to_string();
            let s = subs.entry(name.clone()).or_insert_with(|| Subdomain {
                name,
                wildcard: false,
                certs: 0,
                first_seen: nb.clone(),
                last_seen: nb.clone(),
                latest_expiry: na.clone(),
            });
            s.wildcard |= wildcard;
            s.certs += 1;
            if !nb.is_empty() && (s.first_seen.is_empty() || nb < s.first_seen) {
                s.first_seen = nb.clone();
            }
            if nb > s.last_seen {
                s.last_seen = nb;
            }
            if na > s.latest_expiry {
                s.latest_expiry = na;
            }
        }
    }

    let mut subdomains: Vec<Subdomain> = subs.into_values().collect();
    // Sort by hierarchy: reverse labels so siblings cluster together.
    subdomains.sort_by_key(|s| s.name.rsplit('.').collect::<Vec<_>>().join("."));

    let interesting = subdomains
        .iter()
        .filter(|s| {
            let left = s.name.strip_suffix(&format!(".{domain}")).unwrap_or("");
            left.split(['.', '-']).any(|lbl| INTERESTING.contains(&lbl))
        })
        .map(|s| s.name.clone())
        .collect();

    let mut issuers: Vec<Issuer> = issuers
        .into_iter()
        .map(|(name, certs)| Issuer { name, certs })
        .collect();
    issuers.sort_by(|a, b| b.certs.cmp(&a.certs));

    Ok(CertReport {
        total_certs: entries.len(),
        subdomains,
        issuers,
        interesting,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventories() {
        let j = serde_json::json!([
            {"name_value":"example.com\nwww.example.com","common_name":"example.com","issuer_name":"C=US, O=Let's Encrypt, CN=R3","not_before":"2024-01-01T00:00:00","not_after":"2024-04-01T00:00:00"},
            {"name_value":"*.dev.example.com","common_name":"*.dev.example.com","issuer_name":"C=US, O=Let's Encrypt, CN=R11","not_before":"2025-06-01T00:00:00","not_after":"2025-09-01T00:00:00"},
            {"name_value":"www.example.com\nevil.com","common_name":"www.example.com","issuer_name":"C=BE, O=GlobalSign nv-sa, CN=x","not_before":"2023-01-01T00:00:00","not_after":"2024-01-01T00:00:00"}
        ])
        .to_string();
        let r = analyze(&j, "example.com").unwrap();
        assert_eq!(r.total_certs, 3);
        let names: Vec<&str> = r.subdomains.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["example.com", "dev.example.com", "www.example.com"]
        );
        let www = r
            .subdomains
            .iter()
            .find(|s| s.name == "www.example.com")
            .unwrap();
        assert_eq!(www.certs, 2);
        assert_eq!(www.first_seen, "2023-01-01");
        assert_eq!(www.last_seen, "2024-01-01");
        assert!(
            r.subdomains
                .iter()
                .find(|s| s.name == "dev.example.com")
                .unwrap()
                .wildcard
        );
        assert_eq!(r.interesting, vec!["dev.example.com"]);
        assert_eq!(r.issuers[0].name, "Let's Encrypt");
        assert_eq!(r.issuers[0].certs, 2);
    }
}
