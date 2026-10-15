//! IP → ASN enrichment using Team Cymru's DNS interface, queried through
//! DNS-over-HTTPS so it works from a static page with no API key.
//!
//!   4.3.2.1.origin.asn.cymru.com TXT → "15169 | 1.2.3.0/24 | US | arin | 2000-03-30"
//!   AS15169.asn.cymru.com        TXT → "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"

use serde::Serialize;
use std::net::IpAddr;

use crate::util::unquote_txt;

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct Origin {
    pub asn: String,
    pub prefix: String,
    pub country: String,
    pub registry: String,
    pub allocated: String,
}

#[derive(Serialize, Debug, Default, PartialEq)]
pub struct AsName {
    pub asn: String,
    pub country: String,
    pub registry: String,
    pub name: String,
}

pub fn origin_query(ip: &str) -> Option<String> {
    match ip.trim().parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!(
                "{}.{}.{}.{}.origin.asn.cymru.com",
                o[3], o[2], o[1], o[0]
            ))
        }
        IpAddr::V6(v6) => {
            let hex: String = v6.octets().iter().map(|b| format!("{:02x}", b)).collect();
            let nib: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
            Some(format!("{}.origin6.asn.cymru.com", nib.join(".")))
        }
    }
}

fn fields(txt: &str) -> Vec<String> {
    unquote_txt(txt)
        .split('|')
        .map(|s| s.trim().to_string())
        .collect()
}

pub fn parse_origin(txt: &str) -> Option<Origin> {
    let f = fields(txt);
    if f.len() < 3 || f[0].is_empty() {
        return None;
    }
    // Multi-origin prefixes list several ASNs separated by spaces; keep the first.
    Some(Origin {
        asn: f[0].split_whitespace().next().unwrap_or("").to_string(),
        prefix: f.get(1).cloned().unwrap_or_default(),
        country: f.get(2).cloned().unwrap_or_default(),
        registry: f.get(3).cloned().unwrap_or_default(),
        allocated: f.get(4).cloned().unwrap_or_default(),
    })
}

pub fn parse_name(txt: &str) -> Option<AsName> {
    let f = fields(txt);
    if f.len() < 5 {
        return None;
    }
    Some(AsName {
        asn: f[0].clone(),
        country: f[1].clone(),
        registry: f[2].clone(),
        name: f[4].clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries() {
        assert_eq!(
            origin_query("8.8.4.4").unwrap(),
            "4.4.8.8.origin.asn.cymru.com"
        );
        assert!(origin_query("2001:4860::8888")
            .unwrap()
            .ends_with(".origin6.asn.cymru.com"));
        assert!(origin_query("x").is_none());
    }

    #[test]
    fn parses() {
        let o = parse_origin("\"15169 | 8.8.4.0/24 | US | arin | 2023-12-28\"").unwrap();
        assert_eq!(o.asn, "15169");
        assert_eq!(o.prefix, "8.8.4.0/24");
        assert_eq!(o.country, "US");
        let n = parse_name("\"15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US\"").unwrap();
        assert_eq!(n.name, "GOOGLE - Google LLC, US");
    }
}
