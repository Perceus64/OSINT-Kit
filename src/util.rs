use std::net::IpAddr;

/// Strip scheme, credentials, port, path and a leading "www." and validate
/// the remainder as a hostname with at least one dot.
pub fn normalize_domain(input: &str) -> Option<String> {
    let mut s = crate::ioc::refang(input.trim()).to_ascii_lowercase();
    if let Some(i) = s.find("://") {
        s = s[i + 3..].to_string();
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s.truncate(i);
    }
    if let Some(i) = s.rfind('@') {
        s = s[i + 1..].to_string();
    }
    if let Some(i) = s.find(':') {
        s.truncate(i);
    }
    let s = s.trim_end_matches('.');
    let s = s.strip_prefix("www.").unwrap_or(s);
    if is_hostname(s) {
        Some(s.to_string())
    } else {
        None
    }
}

pub fn is_hostname(s: &str) -> bool {
    if s.len() > 253 || !s.contains('.') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let tld = labels.last().unwrap();
    if tld.len() < 2 || tld.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    labels.iter().all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

pub fn ptr_name(ip: &str) -> Option<String> {
    match ip.trim().parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]))
        }
        IpAddr::V6(v6) => {
            let hex: String = v6.octets().iter().map(|b| format!("{:02x}", b)).collect();
            let nibbles: Vec<String> = hex.chars().rev().map(|c| c.to_string()).collect();
            Some(format!("{}.ip6.arpa", nibbles.join(".")))
        }
    }
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse the date part of an ISO-8601 timestamp ("2005-03-01T00:00:00Z")
/// into days since the Unix epoch.
pub fn iso_to_days(s: &str) -> Option<i64> {
    let date = s.get(0..10)?;
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// DNS TXT data from DoH JSON is a sequence of quoted chunks:
/// `"v=spf1 include:a " "include:b -all"`. Join them back into one string.
pub fn unquote_txt(data: &str) -> String {
    let t = data.trim();
    if !t.starts_with('"') {
        return t.to_string();
    }
    let mut out = String::new();
    let mut in_q = false;
    let mut chars = t.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => in_q = !in_q,
            '\\' if in_q => {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            }
            _ if in_q => out.push(c),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(
            normalize_domain("https://www.Example.com/a?b").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_domain("mail.aust.edu.lb:443").as_deref(),
            Some("mail.aust.edu.lb")
        );
        assert_eq!(normalize_domain("evil[.]com").as_deref(), Some("evil.com"));
        assert_eq!(normalize_domain("not a domain"), None);
        assert_eq!(normalize_domain("1.2.3.4"), None);
    }

    #[test]
    fn ptr() {
        assert_eq!(ptr_name("8.8.4.4").unwrap(), "4.4.8.8.in-addr.arpa");
        assert!(ptr_name("2001:db8::1")
            .unwrap()
            .ends_with("8.b.d.0.1.0.0.2.ip6.arpa"));
    }

    #[test]
    fn dates() {
        assert_eq!(iso_to_days("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(iso_to_days("2000-03-01"), Some(11017));
    }

    #[test]
    fn txt() {
        assert_eq!(unquote_txt("\"v=spf1 \" \"-all\""), "v=spf1 -all");
        assert_eq!(unquote_txt("plain"), "plain");
    }
}
