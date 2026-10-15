//! DNS footprint analysis: records, email-security posture, and service
//! fingerprinting from verification tokens, SPF includes, MX and NS hosts.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::util::unquote_txt;

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Status", default)]
    status: i64,
    #[serde(rename = "AD", default)]
    ad: bool,
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

#[derive(Deserialize)]
struct DohAnswer {
    name: String,
    #[serde(rename = "type")]
    rtype: u16,
    #[serde(rename = "TTL", default)]
    ttl: u32,
    data: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct Record {
    pub rtype: String,
    pub name: String,
    pub ttl: u32,
    pub value: String,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Good,
    Info,
    Warn,
    Bad,
}

#[derive(Serialize, Debug, Clone)]
pub struct Finding {
    pub level: Level,
    pub title: String,
    pub detail: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct Service {
    pub name: String,
    pub evidence: String,
}

#[derive(Serialize, Debug, Default)]
pub struct DnsReport {
    pub exists: bool,
    pub dnssec: bool,
    pub records: Vec<Record>,
    pub ips: Vec<String>,
    pub findings: Vec<Finding>,
    pub services: Vec<Service>,
    pub score: u8,
    pub grade: String,
}

fn type_name(t: u16) -> String {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        257 => "CAA",
        _ => return format!("TYPE{}", t),
    }
    .to_string()
}

fn finding(level: Level, title: &str, detail: impl Into<String>) -> Finding {
    Finding {
        level,
        title: title.to_string(),
        detail: detail.into(),
    }
}

// (substring to look for, service name)
const TXT_TOKENS: &[(&str, &str)] = &[
    (
        "google-site-verification",
        "Google Search Console / Workspace",
    ),
    ("ms=ms", "Microsoft 365 (tenant)"),
    ("facebook-domain-verification", "Meta Business"),
    ("apple-domain-verification", "Apple"),
    ("atlassian-domain-verification", "Atlassian"),
    ("docusign", "DocuSign"),
    ("adobe-idp-site-verification", "Adobe"),
    ("stripe-verification", "Stripe"),
    ("zoom-domain-verification", "Zoom"),
    ("zoom_verify", "Zoom"),
    ("slack-domain-verification", "Slack"),
    ("hubspot-developer-verification", "HubSpot"),
    ("globalsign-domain-verification", "GlobalSign"),
    ("_globalsign", "GlobalSign"),
    ("amazonses", "Amazon SES"),
    ("dropbox-domain-verification", "Dropbox"),
    ("openai-domain-verification", "OpenAI"),
    ("anthropic-domain-verification", "Anthropic"),
    ("cisco-ci-domain-verification", "Cisco Webex"),
    ("webexdomainverification", "Cisco Webex"),
    ("miro-verification", "Miro"),
    ("canva-site-verification", "Canva"),
    ("yandex-verification", "Yandex"),
    ("have-i-been-pwned-verification", "Have I Been Pwned"),
    ("mailru-verification", "Mail.ru"),
    ("brevo-code", "Brevo"),
    ("onetrust-domain-verification", "OneTrust"),
    ("knowbe4-site-verification", "KnowBe4"),
    ("citrix-verification", "Citrix"),
    ("teamviewer-sso-verification", "TeamViewer"),
    ("pinterest-site-verification", "Pinterest"),
    ("github-verification", "GitHub"),
];

const SPF_INCLUDES: &[(&str, &str)] = &[
    ("_spf.google.com", "Google Workspace (mail)"),
    ("spf.protection.outlook.com", "Microsoft 365 (mail)"),
    ("sendgrid.net", "SendGrid"),
    ("mailgun.org", "Mailgun"),
    ("amazonses.com", "Amazon SES"),
    ("servers.mcsv.net", "Mailchimp"),
    ("mandrillapp.com", "Mailchimp Transactional"),
    ("zoho", "Zoho Mail"),
    ("_spf.salesforce.com", "Salesforce"),
    ("spf.mandrillapp.com", "Mandrill"),
    ("sparkpostmail.com", "SparkPost"),
    ("_spf.mlsend.com", "MailerLite"),
    ("spf.brevo.com", "Brevo"),
    ("sendinblue.com", "Brevo"),
    ("mktomail.com", "Marketo"),
    ("hubspotemail.net", "HubSpot"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast", "Mimecast"),
    ("zendesk.com", "Zendesk"),
    ("freshdesk.com", "Freshdesk"),
    ("protonmail.ch", "Proton Mail"),
];

const MX_HOSTS: &[(&str, &str)] = &[
    ("google.com", "Google Workspace (mail)"),
    ("googlemail.com", "Google Workspace (mail)"),
    ("mail.protection.outlook.com", "Microsoft 365 (mail)"),
    ("pphosted.com", "Proofpoint"),
    ("mimecast", "Mimecast"),
    ("barracudanetworks.com", "Barracuda"),
    ("zoho", "Zoho Mail"),
    ("protonmail.ch", "Proton Mail"),
    ("messagelabs.com", "Broadcom Email Security"),
    ("iphmx.com", "Cisco Secure Email"),
    ("secureserver.net", "GoDaddy Mail"),
    ("yandex", "Yandex Mail"),
    ("mailgun.org", "Mailgun"),
    ("amazonaws.com", "Amazon SES / WorkMail"),
    ("ovh.net", "OVH Mail"),
];

const NS_HOSTS: &[(&str, &str)] = &[
    ("cloudflare.com", "Cloudflare DNS"),
    ("awsdns", "Amazon Route 53"),
    ("azure-dns", "Azure DNS"),
    ("googledomains.com", "Google Domains DNS"),
    ("ns-cloud", "Google Cloud DNS"),
    ("domaincontrol.com", "GoDaddy DNS"),
    ("nsone.net", "NS1"),
    ("ultradns", "UltraDNS"),
    ("dnsmadeeasy.com", "DNS Made Easy"),
    ("akam.net", "Akamai DNS"),
    ("registrar-servers.com", "Namecheap DNS"),
    ("digitalocean.com", "DigitalOcean DNS"),
    ("linode.com", "Linode DNS"),
    ("hetzner", "Hetzner DNS"),
    ("ovh.net", "OVH DNS"),
    ("wixdns.net", "Wix"),
    ("squarespacedns.com", "Squarespace"),
    ("vercel-dns.com", "Vercel DNS"),
    ("netlify", "Netlify DNS"),
];

fn add_service(services: &mut Vec<Service>, name: &str, evidence: &str) {
    if !services.iter().any(|s| s.name == name) {
        services.push(Service {
            name: name.to_string(),
            evidence: evidence.to_string(),
        });
    }
}

pub fn analyze(bundle_json: &str) -> Result<DnsReport, String> {
    let raw: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(bundle_json).map_err(|e| format!("bad DNS bundle: {e}"))?;

    let mut parsed: BTreeMap<String, DohResponse> = BTreeMap::new();
    for (k, v) in raw {
        if let Ok(r) = serde_json::from_value::<DohResponse>(v) {
            parsed.insert(k.to_ascii_uppercase(), r);
        }
    }

    let mut rep = DnsReport::default();

    // Collect records from the apex queries (skip the helper lookups like _dmarc).
    let apex = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "CAA", "SOA"];
    for key in apex {
        if let Some(r) = parsed.get(key) {
            for a in &r.answer {
                let value = if a.rtype == 16 {
                    unquote_txt(&a.data)
                } else {
                    a.data.clone()
                };
                rep.records.push(Record {
                    rtype: type_name(a.rtype),
                    name: a.name.trim_end_matches('.').to_string(),
                    ttl: a.ttl,
                    value,
                });
            }
        }
    }
    // Dedupe (CNAME chains repeat across query types).
    let mut seen = std::collections::HashSet::new();
    rep.records
        .retain(|r| seen.insert((r.rtype.clone(), r.name.clone(), r.value.clone())));

    rep.exists = parsed
        .values()
        .any(|r| r.status == 0 && !r.answer.is_empty())
        || parsed.get("SOA").map(|r| r.status == 0).unwrap_or(false);
    rep.dnssec = parsed.get("A").map(|r| r.ad).unwrap_or(false)
        || parsed.get("SOA").map(|r| r.ad).unwrap_or(false);

    rep.ips = rep
        .records
        .iter()
        .filter(|r| r.rtype == "A" || r.rtype == "AAAA")
        .map(|r| r.value.clone())
        .collect();

    if !rep.exists {
        rep.findings.push(finding(
            Level::Bad,
            "Domain does not resolve",
            "No answers came back (NXDOMAIN or no records). Check the spelling.",
        ));
        rep.score = 0;
        rep.grade = "–".into();
        return Ok(rep);
    }

    let txts: Vec<String> = rep
        .records
        .iter()
        .filter(|r| r.rtype == "TXT")
        .map(|r| r.value.clone())
        .collect();
    let mx: Vec<String> = rep
        .records
        .iter()
        .filter(|r| r.rtype == "MX")
        .map(|r| r.value.to_ascii_lowercase())
        .collect();
    let ns: Vec<String> = rep
        .records
        .iter()
        .filter(|r| r.rtype == "NS")
        .map(|r| r.value.to_ascii_lowercase())
        .collect();
    let caa: Vec<String> = rep
        .records
        .iter()
        .filter(|r| r.rtype == "CAA")
        .map(|r| r.value.clone())
        .collect();

    // ---- SPF
    let spf: Vec<&String> = txts
        .iter()
        .filter(|t| t.to_ascii_lowercase().starts_with("v=spf1"))
        .collect();
    match spf.len() {
        0 => rep.findings.push(finding(
            Level::Bad,
            "No SPF record",
            "Anyone can send mail claiming to be from this domain without failing SPF.",
        )),
        1 => {
            let s = spf[0].to_ascii_lowercase();
            let terms: Vec<&str> = s.split_whitespace().collect();
            let lookups = terms
                .iter()
                .filter(|t| {
                    let t = t.trim_start_matches(['+', '-', '~', '?']);
                    t.starts_with("include:")
                        || t == "a"
                        || t.starts_with("a:")
                        || t == "mx"
                        || t.starts_with("mx:")
                        || t.starts_with("ptr")
                        || t.starts_with("exists:")
                        || t.starts_with("redirect=")
                })
                .count();
            let all = terms.iter().find(|t| t.ends_with("all") && t.len() <= 4);
            match all.copied() {
                Some("-all") => {
                    rep.findings
                        .push(finding(Level::Good, "SPF hard fail (-all)", spf[0].clone()))
                }
                Some("~all") => rep.findings.push(finding(
                    Level::Info,
                    "SPF soft fail (~all)",
                    format!(
                        "Unlisted senders are marked suspicious but not rejected. {}",
                        spf[0]
                    ),
                )),
                Some("?all") => rep.findings.push(finding(
                    Level::Warn,
                    "SPF neutral (?all)",
                    format!("SPF makes no claim about other senders. {}", spf[0]),
                )),
                Some("+all") | Some("all") => rep.findings.push(finding(
                    Level::Bad,
                    "SPF allows everyone (+all)",
                    format!("Any server on the internet passes SPF. {}", spf[0]),
                )),
                _ if s.contains("redirect=") => {
                    rep.findings
                        .push(finding(Level::Info, "SPF uses redirect", spf[0].clone()))
                }
                _ => rep.findings.push(finding(
                    Level::Warn,
                    "SPF has no 'all' mechanism",
                    format!("Defaults to neutral for unlisted senders. {}", spf[0]),
                )),
            }
            if lookups > 10 {
                rep.findings.push(finding(
                    Level::Warn,
                    "SPF may exceed 10 DNS lookups",
                    format!("{lookups} lookup terms at the top level alone; receivers return permerror past 10."),
                ));
            }
            if s == "v=spf1 -all" && mx.is_empty() {
                rep.findings.push(finding(
                    Level::Good,
                    "Parked for email",
                    "The domain declares it sends no mail and has no MX — a good anti-spoofing setup.",
                ));
            }
            for (needle, name) in SPF_INCLUDES {
                if s.contains(needle) {
                    add_service(
                        &mut rep.services,
                        name,
                        &format!("SPF include contains {needle}"),
                    );
                }
            }
        }
        n => rep.findings.push(finding(
            Level::Bad,
            "Multiple SPF records",
            format!("{n} records start with v=spf1; receivers treat this as a permanent error."),
        )),
    }

    // ---- DMARC
    let dmarc = parsed
        .get("DMARC")
        .map(|r| {
            r.answer
                .iter()
                .filter(|a| a.rtype == 16)
                .map(|a| unquote_txt(&a.data))
                .filter(|t| t.to_ascii_lowercase().starts_with("v=dmarc1"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if dmarc.is_empty() {
        rep.findings.push(finding(
            Level::Bad,
            "No DMARC record",
            "Nothing at _dmarc tells receivers what to do with spoofed mail.",
        ));
    } else {
        let d = &dmarc[0];
        let tags: BTreeMap<String, String> = d
            .split(';')
            .filter_map(|kv| {
                let mut it = kv.splitn(2, '=');
                Some((
                    it.next()?.trim().to_ascii_lowercase(),
                    it.next()?.trim().to_string(),
                ))
            })
            .collect();
        let p = tags
            .get("p")
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        match p.as_str() {
            "reject" => rep
                .findings
                .push(finding(Level::Good, "DMARC policy: reject", d.clone())),
            "quarantine" => {
                rep.findings
                    .push(finding(Level::Good, "DMARC policy: quarantine", d.clone()))
            }
            "none" => rep.findings.push(finding(
                Level::Warn,
                "DMARC policy: none (monitor only)",
                format!("Spoofed mail is reported but still delivered. {d}"),
            )),
            _ => rep.findings.push(finding(
                Level::Warn,
                "DMARC record has no valid p= tag",
                d.clone(),
            )),
        }
        if let Some(pct) = tags.get("pct").and_then(|v| v.parse::<u32>().ok()) {
            if pct < 100 {
                rep.findings.push(finding(
                    Level::Warn,
                    "DMARC applies to a fraction of mail",
                    format!("pct={pct}: the policy only covers {pct}% of failing messages."),
                ));
            }
        }
        if let Some(rua) = tags.get("rua") {
            rep.findings.push(finding(
                Level::Info,
                "DMARC aggregate reports go to",
                rua.clone(),
            ));
        }
    }

    // ---- MX
    if mx.is_empty() {
        rep.findings.push(finding(
            Level::Info,
            "No MX records",
            "The domain doesn't receive email.",
        ));
    }
    for m in &mx {
        for (needle, name) in MX_HOSTS {
            if m.contains(needle) {
                add_service(
                    &mut rep.services,
                    name,
                    &format!("MX {}", m.trim_end_matches('.')),
                );
            }
        }
    }

    // ---- MTA-STS
    let has_mta_sts = parsed
        .get("MTASTS")
        .map(|r| {
            r.answer.iter().any(|a| {
                unquote_txt(&a.data)
                    .to_ascii_lowercase()
                    .starts_with("v=stsv1")
            })
        })
        .unwrap_or(false);
    if has_mta_sts {
        rep.findings.push(finding(
            Level::Good,
            "MTA-STS enabled",
            "Inbound mail requires TLS.",
        ));
    } else if !mx.is_empty() {
        rep.findings.push(finding(
            Level::Info,
            "No MTA-STS",
            "Senders may fall back to unencrypted delivery if TLS is stripped.",
        ));
    }

    // ---- CAA
    if caa.is_empty() {
        rep.findings.push(finding(
            Level::Info,
            "No CAA records",
            "Any certificate authority may issue certificates for this domain.",
        ));
    } else {
        rep.findings.push(finding(
            Level::Good,
            "CAA restricts certificate issuers",
            caa.join(" · "),
        ));
    }

    // ---- DNSSEC
    if rep.dnssec {
        rep.findings.push(finding(
            Level::Good,
            "DNSSEC validated",
            "The resolver authenticated these answers.",
        ));
    } else {
        rep.findings.push(finding(
            Level::Info,
            "DNSSEC not validated",
            "Answers aren't cryptographically signed (common, but spoofable on hostile networks).",
        ));
    }

    // ---- Service fingerprinting from TXT tokens and NS
    for t in &txts {
        let lt = t.to_ascii_lowercase();
        for (needle, name) in TXT_TOKENS {
            if lt.starts_with(needle) || lt.contains(&format!("{needle}=")) {
                add_service(&mut rep.services, name, &format!("TXT {}", truncate(t, 60)));
            }
        }
    }
    for n in &ns {
        for (needle, name) in NS_HOSTS {
            if n.contains(needle) {
                add_service(
                    &mut rep.services,
                    name,
                    &format!("NS {}", n.trim_end_matches('.')),
                );
            }
        }
    }

    // ---- Score
    let mut score: i32 = 100;
    for f in &rep.findings {
        score -= match f.level {
            Level::Bad => 25,
            Level::Warn => 15,
            _ => 0,
        };
    }
    rep.score = score.clamp(0, 100) as u8;
    rep.grade = match rep.score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
    .to_string();

    Ok(rep)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> String {
        serde_json::json!({
            "A": {"Status":0,"AD":true,"Answer":[{"name":"example.com.","type":1,"TTL":300,"data":"93.184.216.34"}]},
            "MX": {"Status":0,"Answer":[{"name":"example.com.","type":15,"TTL":300,"data":"1 aspmx.l.google.com."}]},
            "NS": {"Status":0,"Answer":[{"name":"example.com.","type":2,"TTL":300,"data":"ns1.cloudflare.com."}]},
            "TXT": {"Status":0,"Answer":[
                {"name":"example.com.","type":16,"TTL":300,"data":"\"v=spf1 include:_spf.google.com \" \"~all\""},
                {"name":"example.com.","type":16,"TTL":300,"data":"\"google-site-verification=abc\""}
            ]},
            "DMARC": {"Status":0,"Answer":[{"name":"_dmarc.example.com.","type":16,"TTL":300,"data":"\"v=DMARC1; p=none; rua=mailto:d@example.com\""}]},
            "CAA": {"Status":0},
            "SOA": {"Status":0}
        })
        .to_string()
    }

    #[test]
    fn analyzes_bundle() {
        let r = analyze(&bundle()).unwrap();
        assert!(r.exists);
        assert!(r.dnssec);
        assert_eq!(r.ips, vec!["93.184.216.34"]);
        let titles: Vec<&str> = r.findings.iter().map(|f| f.title.as_str()).collect();
        assert!(titles.contains(&"SPF soft fail (~all)"));
        assert!(titles.contains(&"DMARC policy: none (monitor only)"));
        assert!(titles.contains(&"No CAA records"));
        let svc: Vec<&str> = r.services.iter().map(|s| s.name.as_str()).collect();
        assert!(svc.contains(&"Google Workspace (mail)"));
        assert!(svc.contains(&"Cloudflare DNS"));
        assert!(svc.contains(&"Google Search Console / Workspace"));
        assert_eq!(r.score, 85);
        assert_eq!(r.grade, "B");
    }

    #[test]
    fn nxdomain() {
        let b = r#"{"A":{"Status":3},"SOA":{"Status":3}}"#;
        let r = analyze(b).unwrap();
        assert!(!r.exists);
        assert_eq!(r.findings[0].level, Level::Bad);
    }

    #[test]
    fn multiple_spf() {
        let b = serde_json::json!({
            "A": {"Status":0,"Answer":[{"name":"x.com.","type":1,"TTL":1,"data":"1.1.1.1"}]},
            "TXT": {"Status":0,"Answer":[
                {"name":"x.com.","type":16,"TTL":1,"data":"\"v=spf1 -all\""},
                {"name":"x.com.","type":16,"TTL":1,"data":"\"v=spf1 +all\""}
            ]}
        })
        .to_string();
        let r = analyze(&b).unwrap();
        assert!(r.findings.iter().any(|f| f.title == "Multiple SPF records"));
    }
}
