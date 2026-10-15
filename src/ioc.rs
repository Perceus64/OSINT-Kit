//! Indicator-of-compromise extraction, (de|re)fanging and IP classification.

use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

#[derive(Serialize, Debug, Default)]
pub struct Iocs {
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub emails: Vec<String>,
    pub md5: Vec<String>,
    pub sha1: Vec<String>,
    pub sha256: Vec<String>,
    pub cves: Vec<String>,
    pub total: usize,
}

#[derive(Serialize, Debug)]
pub struct IpClass {
    pub ip: String,
    pub valid: bool,
    pub version: u8,
    pub kind: String,
    pub routable: bool,
}

struct Patterns {
    url: Regex,
    email: Regex,
    ipv4: Regex,
    ipv6: Regex,
    domain: Regex,
    md5: Regex,
    sha1: Regex,
    sha256: Regex,
    cve: Regex,
    refang: Vec<(Regex, &'static str)>,
}

fn pats() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        url: Regex::new(r#"(?i)\b(?:https?|ftp)://[^\s"'<>(){}\[\]|\\^`]+"#).unwrap(),
        email: Regex::new(r"(?i)\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b").unwrap(),
        ipv4: Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        )
        .unwrap(),
        ipv6: Regex::new(r"(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}").unwrap(),
        domain: Regex::new(
            r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}\b",
        )
        .unwrap(),
        md5: Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap(),
        sha1: Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap(),
        sha256: Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap(),
        cve: Regex::new(r"(?i)\bCVE-\d{4}-\d{4,7}\b").unwrap(),
        refang: vec![
            (
                Regex::new(r"(?i)\bh(?:xx|\[xx\]|XX)p(s?)\b").unwrap(),
                "http$1",
            ),
            (Regex::new(r"(?i)\bfxp\b").unwrap(), "ftp"),
            (
                Regex::new(r"(?i)\s?[\[\(\{]\s?(?:\.|dot)\s?[\]\)\}]\s?").unwrap(),
                ".",
            ),
            (Regex::new(r"\\\.").unwrap(), "."),
            (
                Regex::new(r"(?i)\s?[\[\(\{]\s?(?:@|at)\s?[\]\)\}]\s?").unwrap(),
                "@",
            ),
            (Regex::new(r"[\[\(\{]://[\]\)\}]").unwrap(), "://"),
            (Regex::new(r"[\[\(\{]:[\]\)\}]").unwrap(), ":"),
            (Regex::new(r"[\[\(\{]/[\]\)\}]").unwrap(), "/"),
        ],
    })
}

/// File extensions and code-ish suffixes that look like TLDs but almost
/// never are in threat reports.
const NOT_TLDS: &[&str] = &[
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "msi", "lnk", "scr",
    "jar", "py", "sh", "bin", "dat", "tmp", "log", "txt", "ini", "cfg", "conf", "json", "xml",
    "yml", "yaml", "csv", "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx",
    "rtf", "zip", "rar", "gz", "tar", "7z", "iso", "img", "png", "jpg", "jpeg", "gif", "bmp",
    "svg", "mp3", "mp4", "avi", "html", "htm", "php", "asp", "aspx", "jsp", "css", "c", "h", "cpp",
    "rs", "go", "java", "class", "rb", "pl", "md", "so", "dylib", "apk", "dmg", "pkg", "deb",
    "rpm", "eml", "msg", "db", "sqlite", "bak", "old", "swp", "lock", "toml", "ts", "tsx", "jsx",
    "vue", "map", "min", "wasm",
];

pub fn refang(text: &str) -> String {
    let mut s = text.to_string();
    for (re, rep) in &pats().refang {
        s = re.replace_all(&s, *rep).into_owned();
    }
    s
}

pub fn defang(ioc: &str) -> String {
    let s = ioc.trim();
    let s = Regex::new(r"(?i)^http")
        .unwrap()
        .replace(s, "hxxp")
        .into_owned();
    let s = Regex::new(r"(?i)^ftp")
        .unwrap()
        .replace(&s, "fxp")
        .into_owned();
    let s = s.replacen("://", "[://]", 1);
    // Only bracket the dots in the host part; leave paths readable.
    let (host_end, prefix) = match s.find("[://]") {
        Some(i) => {
            let rest = &s[i + 5..];
            let end = rest
                .find(['/', '?', '#'])
                .map(|j| i + 5 + j)
                .unwrap_or(s.len());
            (end, i + 5)
        }
        None => (s.len(), 0),
    };
    let host = s[prefix..host_end].replace('.', "[.]").replace('@', "[@]");
    format!("{}{}{}", &s[..prefix], host, &s[host_end..])
}

fn push_unique(set: &mut BTreeSet<String>, v: String) {
    set.insert(v);
}

pub fn extract(text: &str) -> Iocs {
    let p = pats();
    let text = refang(text);

    let mut urls = BTreeSet::new();
    let mut emails = BTreeSet::new();
    let mut v4 = BTreeSet::new();
    let mut v6 = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut md5 = BTreeSet::new();
    let mut sha1 = BTreeSet::new();
    let mut sha256 = BTreeSet::new();
    let mut cves = BTreeSet::new();

    for m in p.url.find_iter(&text) {
        let u = m
            .as_str()
            .trim_end_matches(['.', ',', ';', ':', '!', '?', '\'', '"']);
        push_unique(&mut urls, u.to_string());
    }
    for m in p.email.find_iter(&text) {
        push_unique(&mut emails, m.as_str().to_ascii_lowercase());
    }
    for m in p.ipv4.find_iter(&text) {
        // Skip version strings like 1.2.3.4.5 by checking neighbours.
        let before = text[..m.start()].chars().last();
        let after = text[m.end()..].chars().next();
        let dotted = |c: Option<char>, other: Option<char>| {
            c == Some('.') && other.map(|o| o.is_ascii_digit()).unwrap_or(false)
        };
        let next2 = text[m.end()..].chars().nth(1);
        let prev2 = text[..m.start()].chars().rev().nth(1);
        if dotted(after, next2) || dotted(before, prev2) {
            continue;
        }
        push_unique(&mut v4, m.as_str().to_string());
    }
    for m in p.ipv6.find_iter(&text) {
        let cand = m.as_str().trim_matches(':');
        let cand = if m.as_str().starts_with("::") || m.as_str().ends_with("::") {
            m.as_str()
        } else {
            cand
        };
        if cand.matches(':').count() >= 2 {
            if let Ok(a) = cand.parse::<Ipv6Addr>() {
                // Ignore "::" alone and obvious times like 12:30:45.
                if !a.is_unspecified() && cand.len() > 7 {
                    push_unique(&mut v6, a.to_string());
                }
            }
        }
    }
    let email_spans: Vec<(usize, usize)> = p
        .email
        .find_iter(&text)
        .map(|m| (m.start(), m.end()))
        .collect();
    for m in p.domain.find_iter(&text) {
        let d = m.as_str().to_ascii_lowercase();
        let tld = d.rsplit('.').next().unwrap_or("");
        if NOT_TLDS.contains(&tld) || tld.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if d.parse::<Ipv4Addr>().is_ok() {
            continue;
        }
        // The local part of an email address isn't a domain.
        let in_local_part = email_spans.iter().any(|(s, e)| {
            m.start() >= *s
                && m.end() <= *e
                && text[*s..m.start()].find('@').is_none()
                && text[m.end()..*e].contains('@')
        });
        if in_local_part {
            continue;
        }
        push_unique(&mut domains, d);
    }
    for m in p.sha256.find_iter(&text) {
        push_unique(&mut sha256, m.as_str().to_ascii_lowercase());
    }
    for m in p.sha1.find_iter(&text) {
        push_unique(&mut sha1, m.as_str().to_ascii_lowercase());
    }
    for m in p.md5.find_iter(&text) {
        push_unique(&mut md5, m.as_str().to_ascii_lowercase());
    }
    for m in p.cve.find_iter(&text) {
        push_unique(&mut cves, m.as_str().to_ascii_uppercase());
    }

    let mut r = Iocs {
        urls: urls.into_iter().collect(),
        domains: domains.into_iter().collect(),
        ipv4: v4.into_iter().collect(),
        ipv6: v6.into_iter().collect(),
        emails: emails.into_iter().collect(),
        md5: md5.into_iter().collect(),
        sha1: sha1.into_iter().collect(),
        sha256: sha256.into_iter().collect(),
        cves: cves.into_iter().collect(),
        total: 0,
    };
    r.total = r.urls.len()
        + r.domains.len()
        + r.ipv4.len()
        + r.ipv6.len()
        + r.emails.len()
        + r.md5.len()
        + r.sha1.len()
        + r.sha256.len()
        + r.cves.len();
    r
}

pub fn classify_ip(ip: &str) -> IpClass {
    let ip_s = ip.trim().to_string();
    let parsed = match ip_s.parse::<IpAddr>() {
        Ok(a) => a,
        Err(_) => {
            return IpClass {
                ip: ip_s,
                valid: false,
                version: 0,
                kind: "invalid".into(),
                routable: false,
            }
        }
    };
    let (version, kind) = match parsed {
        IpAddr::V4(a) => {
            let o = a.octets();
            let kind = if a.is_loopback() {
                "loopback"
            } else if a.is_private() {
                "private (RFC 1918)"
            } else if a.is_link_local() {
                "link-local"
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                "carrier-grade NAT"
            } else if a.is_multicast() {
                "multicast"
            } else if a.is_broadcast() {
                "broadcast"
            } else if a.is_unspecified() || o[0] == 0 {
                "unspecified"
            } else if (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
            {
                "documentation"
            } else if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                "benchmarking"
            } else if o[0] >= 240 {
                "reserved"
            } else {
                "public"
            };
            (4, kind)
        }
        IpAddr::V6(a) => {
            let seg = a.segments();
            let kind = if a.is_loopback() {
                "loopback"
            } else if a.is_unspecified() {
                "unspecified"
            } else if a.is_multicast() {
                "multicast"
            } else if (seg[0] & 0xffc0) == 0xfe80 {
                "link-local"
            } else if (seg[0] & 0xfe00) == 0xfc00 {
                "unique local (private)"
            } else if seg[0] == 0x2001 && seg[1] == 0x0db8 {
                "documentation"
            } else if a.to_ipv4_mapped().is_some() {
                "IPv4-mapped"
            } else if (seg[0] & 0xe000) == 0x2000 {
                "public"
            } else {
                "reserved"
            };
            (6, kind)
        }
    };
    IpClass {
        ip: parsed.to_string(),
        valid: true,
        version,
        routable: kind == "public",
        kind: kind.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refangs() {
        assert_eq!(refang("hxxps://evil[.]com/x"), "https://evil.com/x");
        assert_eq!(refang("bad(dot)site[.]org"), "bad.site.org");
        assert_eq!(refang("user[at]corp[.]com"), "user@corp.com");
        assert_eq!(refang("10[.]0[.]0[.]1"), "10.0.0.1");
    }

    #[test]
    fn defangs() {
        assert_eq!(
            defang("https://evil.com/a.php"),
            "hxxps[://]evil[.]com/a.php"
        );
        assert_eq!(defang("evil.com"), "evil[.]com");
        assert_eq!(defang("1.2.3.4"), "1[.]2[.]3[.]4");
        assert_eq!(
            refang(&defang("https://evil.com/a.php")),
            "https://evil.com/a.php"
        );
    }

    #[test]
    fn extracts() {
        let t = "Beacon to hxxp://c2[.]badhost[.]ru/gate.php from 185.220.101.4 and 10.0.0.5.
                 Dropper invoice.exe (md5 44d88612fea8a8f36de82e1278abb02f,
                 sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f)
                 Contact: phish@lure-mail.com. Exploits CVE-2024-3400. Version 1.2.3.4.5 is not an IP.
                 v6 peer 2001:db8::dead:beef at 12:30:45.";
        let r = extract(t);
        assert_eq!(r.urls, vec!["http://c2.badhost.ru/gate.php"]);
        assert_eq!(r.ipv4, vec!["10.0.0.5", "185.220.101.4"]);
        assert_eq!(r.ipv6, vec!["2001:db8::dead:beef"]);
        assert!(r.domains.contains(&"c2.badhost.ru".to_string()));
        assert!(r.domains.contains(&"lure-mail.com".to_string()));
        assert!(!r
            .domains
            .iter()
            .any(|d| d.ends_with(".exe") || d.ends_with(".php")));
        assert_eq!(r.emails, vec!["phish@lure-mail.com"]);
        assert_eq!(r.md5, vec!["44d88612fea8a8f36de82e1278abb02f"]);
        assert_eq!(r.sha256.len(), 1);
        assert!(r.sha1.is_empty());
        assert_eq!(r.cves, vec!["CVE-2024-3400"]);
    }

    #[test]
    fn classifies() {
        assert_eq!(classify_ip("8.8.8.8").kind, "public");
        assert!(classify_ip("8.8.8.8").routable);
        assert_eq!(classify_ip("192.168.1.1").kind, "private (RFC 1918)");
        assert_eq!(classify_ip("100.72.0.1").kind, "carrier-grade NAT");
        assert_eq!(classify_ip("2001:db8::1").kind, "documentation");
        assert_eq!(classify_ip("2606:4700::1111").kind, "public");
        assert!(!classify_ip("nope").valid);
    }
}
