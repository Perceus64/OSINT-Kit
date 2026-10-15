//! OSINT Toolkit — analysis core compiled to WebAssembly.
//!
//! The browser does the network fetching (DNS-over-HTTPS, RDAP, certificate
//! transparency) and hands raw responses to these functions; everything that
//! touches user files runs entirely here, so files never leave the machine.
//!
//! Every exported function takes and returns strings (JSON) to keep the JS
//! boundary simple.

use serde::Serialize;
use wasm_bindgen::prelude::*;

pub mod asn;
pub mod certs;
pub mod dns;
pub mod ioc;
pub mod meta;
pub mod rdap;
pub mod util;

fn to_json<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap_or_else(|e| error_json(&e.to_string()))
}

fn error_json(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}

/// Version string, shown in the page footer.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Clean up user input ("https://www.Example.com/path") into a bare domain.
/// Returns an empty string when the input isn't a plausible domain.
#[wasm_bindgen]
pub fn normalize_domain(input: &str) -> String {
    util::normalize_domain(input).unwrap_or_default()
}

/// Analyse a bundle of DNS-over-HTTPS JSON answers.
/// Input: `{"A": <doh json>, "MX": <doh json>, ..., "DMARC": <doh json>}`.
#[wasm_bindgen]
pub fn analyze_dns(bundle_json: &str) -> String {
    match dns::analyze(bundle_json) {
        Ok(r) => to_json(&r),
        Err(e) => error_json(&e),
    }
}

/// Summarise an RDAP domain response. `now_ms` is `Date.now()` from JS.
#[wasm_bindgen]
pub fn analyze_rdap(rdap_json: &str, now_ms: f64) -> String {
    match rdap::analyze(rdap_json, now_ms) {
        Ok(r) => to_json(&r),
        Err(e) => error_json(&e),
    }
}

/// Turn a crt.sh JSON response into a deduplicated subdomain inventory.
#[wasm_bindgen]
pub fn analyze_certs(crtsh_json: &str, domain: &str) -> String {
    match certs::analyze(crtsh_json, domain) {
        Ok(r) => to_json(&r),
        Err(e) => error_json(&e),
    }
}

/// Hash, fingerprint and pull metadata out of a file the user dropped in.
#[wasm_bindgen]
pub fn analyze_file(bytes: &[u8], file_name: &str) -> String {
    to_json(&meta::analyze(bytes, file_name))
}

/// Extract indicators of compromise from free text (refangs first).
#[wasm_bindgen]
pub fn extract_iocs(text: &str) -> String {
    to_json(&ioc::extract(text))
}

/// Make an indicator safe to paste into reports and chats.
#[wasm_bindgen]
pub fn defang(indicator: &str) -> String {
    ioc::defang(indicator)
}

/// Reverse of `defang`.
#[wasm_bindgen]
pub fn refang(text: &str) -> String {
    ioc::refang(text)
}

/// Classify an IP address (public, private, loopback, CGNAT, ...).
#[wasm_bindgen]
pub fn classify_ip(ip: &str) -> String {
    to_json(&ioc::classify_ip(ip))
}

/// Build the reverse-DNS (PTR) query name for an IP, e.g. 1.0.0.127.in-addr.arpa.
#[wasm_bindgen]
pub fn ptr_name(ip: &str) -> String {
    util::ptr_name(ip).unwrap_or_default()
}

/// Team Cymru origin-lookup name for an IP (queried as TXT over DoH).
#[wasm_bindgen]
pub fn asn_origin_query(ip: &str) -> String {
    asn::origin_query(ip).unwrap_or_default()
}

/// Parse a Team Cymru origin TXT answer. Returns "null" if unparseable.
#[wasm_bindgen]
pub fn parse_asn_origin(txt: &str) -> String {
    to_json(&asn::parse_origin(txt))
}

/// Parse a Team Cymru AS-name TXT answer. Returns "null" if unparseable.
#[wasm_bindgen]
pub fn parse_asn_name(txt: &str) -> String {
    to_json(&asn::parse_name(txt))
}

/// Return a copy of a JPEG/PNG with metadata removed (pixels untouched).
/// Returns an empty array for unsupported formats.
#[wasm_bindgen]
pub fn strip_metadata(bytes: &[u8]) -> Vec<u8> {
    meta::strip(bytes).unwrap_or_default()
}
