//! File fingerprinting and metadata extraction. Runs entirely in the
//! browser: hashes, magic-byte type detection, entropy, EXIF (with GPS),
//! PDF info dictionaries, XMP packets, Office/OpenDocument properties, and
//! indicators hidden in the file's printable strings.

use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Serialize, Debug, Default)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct Field {
    pub group: String,
    pub key: String,
    pub value: String,
}

#[derive(Serialize, Debug)]
pub struct Gps {
    pub lat: f64,
    pub lon: f64,
    pub altitude_m: Option<f64>,
}

#[derive(Serialize, Debug, Default)]
pub struct FileReport {
    pub name: String,
    pub size: usize,
    pub detected_type: String,
    pub mime: String,
    pub extension_mismatch: bool,
    pub entropy: f64,
    pub hashes: Hashes,
    pub fields: Vec<Field>,
    pub gps: Option<Gps>,
    pub warnings: Vec<String>,
    pub iocs: crate::ioc::Iocs,
}

fn field(group: &str, key: &str, value: impl Into<String>) -> Field {
    Field {
        group: group.into(),
        key: key.into(),
        value: value.into(),
    }
}

pub fn hashes(bytes: &[u8]) -> Hashes {
    Hashes {
        md5: hex::encode(Md5::digest(bytes)),
        sha1: hex::encode(Sha1::digest(bytes)),
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

/// Shannon entropy in bits per byte (0–8). >7.5 usually means compressed
/// or encrypted content.
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// (label, mime, expected extensions)
pub fn sniff(bytes: &[u8]) -> (&'static str, &'static str, &'static [&'static str]) {
    let b = bytes;
    let starts = |sig: &[u8]| b.len() >= sig.len() && &b[..sig.len()] == sig;
    if starts(b"\xFF\xD8\xFF") {
        ("JPEG image", "image/jpeg", &["jpg", "jpeg", "jfif"])
    } else if starts(b"\x89PNG\r\n\x1a\n") {
        ("PNG image", "image/png", &["png"])
    } else if starts(b"GIF87a") || starts(b"GIF89a") {
        ("GIF image", "image/gif", &["gif"])
    } else if b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        ("WebP image", "image/webp", &["webp"])
    } else if b.len() > 12 && &b[4..8] == b"ftyp" {
        let brand = &b[8..12];
        if brand == b"heic" || brand == b"heix" || brand == b"mif1" || brand == b"msf1" {
            ("HEIF/HEIC image", "image/heic", &["heic", "heif"])
        } else if brand == b"avif" {
            ("AVIF image", "image/avif", &["avif"])
        } else if brand == b"qt  " {
            ("QuickTime video", "video/quicktime", &["mov"])
        } else {
            (
                "MP4 / ISO media",
                "video/mp4",
                &["mp4", "m4a", "m4v", "3gp"],
            )
        }
    } else if starts(b"II*\0") || starts(b"MM\0*") {
        (
            "TIFF image (or camera RAW)",
            "image/tiff",
            &["tif", "tiff", "dng", "nef", "cr2", "arw"],
        )
    } else if starts(b"%PDF-") {
        ("PDF document", "application/pdf", &["pdf"])
    } else if starts(b"PK\x03\x04") {
        (
            "ZIP container",
            "application/zip",
            &[
                "zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "apk", "epub",
            ],
        )
    } else if starts(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        (
            "Legacy Office (OLE2) document",
            "application/x-ole-storage",
            &["doc", "xls", "ppt", "msg"],
        )
    } else if starts(b"MZ") {
        (
            "Windows executable (PE)",
            "application/vnd.microsoft.portable-executable",
            &["exe", "dll", "sys", "scr", "com"],
        )
    } else if starts(b"\x7FELF") {
        (
            "ELF executable",
            "application/x-elf",
            &["", "so", "bin", "elf"],
        )
    } else if starts(b"\xCF\xFA\xED\xFE")
        || starts(b"\xCE\xFA\xED\xFE")
        || starts(b"\xCA\xFE\xBA\xBE")
    {
        (
            "Mach-O executable",
            "application/x-mach-binary",
            &["", "dylib"],
        )
    } else if starts(b"Rar!\x1a\x07") {
        ("RAR archive", "application/vnd.rar", &["rar"])
    } else if starts(b"7z\xBC\xAF\x27\x1C") {
        ("7-Zip archive", "application/x-7z-compressed", &["7z"])
    } else if starts(b"\x1F\x8B") {
        ("Gzip archive", "application/gzip", &["gz", "tgz"])
    } else if starts(b"ID3") || (b.len() > 1 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0) {
        ("MP3 audio", "audio/mpeg", &["mp3"])
    } else if starts(b"{\\rtf") {
        ("RTF document", "application/rtf", &["rtf"])
    } else if starts(b"<?xml") || starts(b"<svg") {
        ("XML / SVG", "application/xml", &["xml", "svg", "plist"])
    } else if starts(b"\0asm") {
        ("WebAssembly module", "application/wasm", &["wasm"])
    } else if b
        .iter()
        .take(4096)
        .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
    {
        (
            "Plain text",
            "text/plain",
            &[
                "txt", "csv", "log", "md", "json", "html", "htm", "js", "py", "eml", "ps1", "bat",
                "sh", "xml", "ini", "cfg",
            ],
        )
    } else {
        ("Unknown binary", "application/octet-stream", &[])
    }
}

fn ext_of(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, e)) if !stem.is_empty() => e.to_ascii_lowercase(),
        _ => String::new(),
    }
}

// ---------------------------------------------------------------- EXIF

fn rational_list(v: &exif::Value) -> Option<Vec<f64>> {
    match v {
        exif::Value::Rational(r) => Some(r.iter().map(|x| x.to_f64()).collect()),
        _ => None,
    }
}

fn dms_to_deg(v: &[f64]) -> Option<f64> {
    Some(v.first()? + v.get(1).unwrap_or(&0.0) / 60.0 + v.get(2).unwrap_or(&0.0) / 3600.0)
}

fn exif_fields(bytes: &[u8], rep: &mut FileReport) {
    // Be lenient: plenty of real-world editors write slightly malformed IFDs.
    let mut reader = exif::Reader::new();
    reader.continue_on_error(true);
    let Ok(ex) = reader
        .read_from_container(&mut Cursor::new(bytes))
        .or_else(|e| e.distill_partial_result(|_| {}))
    else {
        return;
    };
    let mut lat = None;
    let mut lat_ref = String::from("N");
    let mut lon = None;
    let mut lon_ref = String::from("E");
    let mut alt = None;
    let mut alt_below = false;

    for f in ex.fields() {
        match f.tag {
            exif::Tag::GPSLatitude => lat = rational_list(&f.value).and_then(|v| dms_to_deg(&v)),
            exif::Tag::GPSLongitude => lon = rational_list(&f.value).and_then(|v| dms_to_deg(&v)),
            exif::Tag::GPSLatitudeRef => lat_ref = f.display_value().to_string(),
            exif::Tag::GPSLongitudeRef => lon_ref = f.display_value().to_string(),
            exif::Tag::GPSAltitude => {
                alt = rational_list(&f.value).and_then(|v| v.first().copied())
            }
            exif::Tag::GPSAltitudeRef => {
                alt_below = f.display_value().to_string().contains("below")
            }
            exif::Tag::MakerNote
            | exif::Tag::JPEGInterchangeFormat
            | exif::Tag::JPEGInterchangeFormatLength => {}
            _ => {
                let val = f.display_value().with_unit(&ex).to_string();
                if val.len() > 300 || val.trim().is_empty() {
                    continue;
                }
                let group = if f.ifd_num == exif::In::THUMBNAIL {
                    "EXIF (thumbnail)"
                } else if f.tag.context() == exif::Context::Gps {
                    "GPS"
                } else {
                    "EXIF"
                };
                rep.fields
                    .push(field(group, &f.tag.to_string(), val.trim_matches('"')));
            }
        }
    }

    if let (Some(mut la), Some(mut lo)) = (lat, lon) {
        if lat_ref.trim_matches('"').starts_with('S') {
            la = -la;
        }
        if lon_ref.trim_matches('"').starts_with('W') {
            lo = -lo;
        }
        let altitude_m = alt.map(|a| if alt_below { -a } else { a });
        rep.warnings.push(format!(
            "Contains GPS coordinates ({la:.5}, {lo:.5}) — this reveals where the photo was taken. Strip metadata before sharing."
        ));
        rep.gps = Some(Gps {
            lat: la,
            lon: lo,
            altitude_m,
        });
    }
    for key in [
        "BodySerialNumber",
        "LensSerialNumber",
        "CameraOwnerName",
        "Artist",
    ] {
        if rep.fields.iter().any(|f| f.key == key) {
            rep.warnings.push(format!(
                "Contains {key}, which can tie the file to a specific device or person."
            ));
        }
    }
}

// ---------------------------------------------------------------- PDF

fn decode_pdf_string(raw: &[u8]) -> String {
    // UTF-16BE with BOM, else Latin-1/PDFDocEncoding (close enough).
    if raw.len() >= 2 && raw[0] == 0xFE && raw[1] == 0xFF {
        let u: Vec<u16> = raw[2..]
            .chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    } else {
        raw.iter().map(|b| *b as char).collect()
    }
}

/// Read a PDF literal "(...)" or hex "<...>" string starting at `i`.
fn read_pdf_string(b: &[u8], mut i: usize) -> Option<Vec<u8>> {
    while i < b.len() && (b[i] == b' ' || b[i] == b'\r' || b[i] == b'\n') {
        i += 1;
    }
    match b.get(i)? {
        b'(' => {
            let mut out = Vec::new();
            let mut depth = 0;
            i += 1;
            while i < b.len() {
                let c = b[i];
                match c {
                    b'\\' => {
                        i += 1;
                        match b.get(i)? {
                            b'n' => out.push(b'\n'),
                            b'r' => out.push(b'\r'),
                            b't' => out.push(b'\t'),
                            d @ b'0'..=b'7' => {
                                let mut v = (d - b'0') as u32;
                                for _ in 0..2 {
                                    if let Some(n @ b'0'..=b'7') = b.get(i + 1) {
                                        v = v * 8 + (n - b'0') as u32;
                                        i += 1;
                                    }
                                }
                                out.push(v as u8);
                            }
                            other => out.push(*other),
                        }
                    }
                    b'(' => {
                        depth += 1;
                        out.push(c)
                    }
                    b')' => {
                        if depth == 0 {
                            return Some(out);
                        }
                        depth -= 1;
                        out.push(c);
                    }
                    _ => out.push(c),
                }
                i += 1;
                if out.len() > 2000 {
                    return Some(out);
                }
            }
            Some(out)
        }
        b'<' => {
            let end = b[i..].iter().position(|c| *c == b'>')? + i;
            let hexs: String = b[i + 1..end]
                .iter()
                .filter(|c| c.is_ascii_hexdigit())
                .map(|c| *c as char)
                .collect();
            hex::decode(if hexs.len() % 2 == 1 {
                format!("{hexs}0")
            } else {
                hexs
            })
            .ok()
        }
        _ => None,
    }
}

fn pdf_date(s: &str) -> String {
    // D:20230401123000+03'00' -> 2023-04-01 12:30:00 +03:00
    let d = s.trim_start_matches("D:");
    if d.len() >= 14 && d[..14].chars().all(|c| c.is_ascii_digit()) {
        let tz = d[14..].replace('\'', "");
        let tz = if tz.len() >= 5 {
            format!(" {}:{}", &tz[..3], &tz[3..5])
        } else if tz == "Z" {
            " UTC".into()
        } else {
            String::new()
        };
        format!(
            "{}-{}-{} {}:{}:{}{}",
            &d[0..4],
            &d[4..6],
            &d[6..8],
            &d[8..10],
            &d[10..12],
            &d[12..14],
            tz
        )
    } else {
        s.to_string()
    }
}

fn pdf_fields(bytes: &[u8], rep: &mut FileReport) {
    let keys = [
        "Title",
        "Author",
        "Subject",
        "Keywords",
        "Creator",
        "Producer",
        "CreationDate",
        "ModDate",
        "Company",
        "SourceModified",
    ];
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    for key in keys {
        let needle = format!("/{key}");
        let nb = needle.as_bytes();
        let mut start = 0;
        while let Some(pos) = find(&bytes[start..], nb) {
            let at = start + pos + nb.len();
            // Make sure we matched a whole key, not /Titles etc.
            let next = bytes.get(at).copied().unwrap_or(b' ');
            if next == b'(' || next == b'<' || next == b' ' || next == b'\r' || next == b'\n' {
                if let Some(raw) = read_pdf_string(bytes, at) {
                    let mut v = decode_pdf_string(&raw).trim().to_string();
                    if key.ends_with("Date") {
                        v = pdf_date(&v);
                    }
                    if !v.is_empty() && !v.starts_with('<') {
                        found.insert(key.to_string(), v);
                    }
                }
            }
            start = at;
        }
    }
    for (k, v) in found {
        rep.fields.push(field("PDF info", &k, v));
    }
    // Revision count via %%EOF markers (incremental saves).
    let eofs = count(bytes, b"%%EOF");
    if eofs > 1 {
        rep.fields.push(field(
            "PDF info",
            "Incremental saves",
            format!("{}", eofs - 1),
        ));
        rep.warnings.push(format!(
            "PDF was saved incrementally {} time(s); earlier versions of the content may still be recoverable.",
            eofs - 1
        ));
    }
    if find(bytes, b"/JavaScript").is_some() || find(bytes, b"/JS").is_some() {
        rep.warnings.push("PDF contains JavaScript actions.".into());
    }
    if find(bytes, b"/OpenAction").is_some() || find(bytes, b"/Launch").is_some() {
        rep.warnings
            .push("PDF has automatic actions (/OpenAction or /Launch).".into());
    }
    if find(bytes, b"/EmbeddedFile").is_some() {
        rep.warnings
            .push("PDF has embedded file attachments.".into());
    }
    if find(bytes, b"/Encrypt").is_some() {
        rep.warnings
            .push("PDF is encrypted; some metadata may be hidden.".into());
    }
}

// ---------------------------------------------------------------- XML props

/// Grab `<ns:Tag>value</ns:Tag>` pairs from an XML string.
fn xml_props(xml: &str, group: &str, out: &mut Vec<Field>) {
    let re = regex::Regex::new(r"<([A-Za-z][\w-]*:[A-Za-z][\w-]*)(?:\s[^>]*)?>([^<]{1,500})</([A-Za-z][\w-]*:[A-Za-z][\w-]*)>").unwrap();
    let mut seen = std::collections::HashSet::new();
    for c in re.captures_iter(xml) {
        if c[1] != c[3] {
            continue;
        }
        let v = c[2].trim();
        if v.is_empty() || !seen.insert((c[1].to_string(), v.to_string())) {
            continue;
        }
        out.push(field(group, &c[1], xml_unescape(v)));
    }
    // XMP also uses attributes: xmp:CreatorTool="..."
    let attr = regex::Regex::new(r#"\s([a-zA-Z]+:[A-Za-z]+)="([^"]{1,300})""#).unwrap();
    for c in attr.captures_iter(xml) {
        let k = &c[1];
        if k.starts_with("xmlns")
            || k.starts_with("rdf:")
            || k.starts_with("xml:")
            || k.starts_with("x:")
        {
            continue;
        }
        let v = c[2].trim();
        if !v.is_empty() && seen.insert((k.to_string(), v.to_string())) {
            out.push(field(group, k, xml_unescape(v)));
        }
    }
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn xmp_fields(bytes: &[u8], rep: &mut FileReport) {
    let Some(start) = find(bytes, b"<x:xmpmeta") else {
        return;
    };
    let Some(end_rel) = find(&bytes[start..], b"</x:xmpmeta>") else {
        return;
    };
    let xml = String::from_utf8_lossy(&bytes[start..start + end_rel + 12]);
    xml_props(&xml, "XMP", &mut rep.fields);
    for f in rep.fields.iter().filter(|f| f.group == "XMP") {
        if f.key.ends_with("History") || f.key == "stEvt:softwareAgent" {
            rep.warnings
                .push("XMP edit history present — shows which software touched the file.".into());
            break;
        }
    }
}

fn zip_fields(bytes: &[u8], rep: &mut FileReport) {
    let Ok(mut z) = zip::ZipArchive::new(Cursor::new(bytes)) else {
        return;
    };
    let names: Vec<String> = (0..z.len())
        .filter_map(|i| z.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();

    let kind = if names.iter().any(|n| n == "word/document.xml") {
        "Word document (.docx)"
    } else if names.iter().any(|n| n == "xl/workbook.xml") {
        "Excel workbook (.xlsx)"
    } else if names.iter().any(|n| n == "ppt/presentation.xml") {
        "PowerPoint deck (.pptx)"
    } else if names.iter().any(|n| n == "meta.xml") && names.iter().any(|n| n == "content.xml") {
        "OpenDocument file"
    } else if names.iter().any(|n| n == "AndroidManifest.xml") {
        "Android package (.apk)"
    } else if names.iter().any(|n| n == "META-INF/MANIFEST.MF") {
        "Java archive (.jar)"
    } else if names.iter().any(|n| n == "META-INF/container.xml") {
        "EPUB e-book"
    } else {
        ""
    };
    if !kind.is_empty() {
        rep.detected_type = kind.to_string();
    }
    rep.fields
        .push(field("Archive", "Entries", names.len().to_string()));

    for (path, group) in [
        ("docProps/core.xml", "Office core"),
        ("docProps/app.xml", "Office app"),
        ("docProps/custom.xml", "Office custom"),
        ("meta.xml", "OpenDocument meta"),
    ] {
        if let Ok(mut f) = z.by_name(path) {
            let mut s = String::new();
            if f.by_ref().take(512 * 1024).read_to_string(&mut s).is_ok() {
                xml_props(&s, group, &mut rep.fields);
            }
        }
    }
    if names.iter().any(|n| n.ends_with("vbaProject.bin")) {
        rep.warnings
            .push("Contains VBA macros (vbaProject.bin).".into());
    }
    if names.iter().any(|n| n.contains("/embeddings/")) {
        rep.warnings.push("Contains embedded objects.".into());
    }
    if names.iter().any(|n| n == "word/comments.xml") {
        rep.warnings
            .push("Contains reviewer comments (word/comments.xml).".into());
    }
    let rels = names
        .iter()
        .filter(|n| n.ends_with(".rels"))
        .cloned()
        .collect::<Vec<_>>();
    for r in rels {
        if let Ok(mut f) = z.by_name(&r) {
            let mut s = String::new();
            if f.by_ref().take(256 * 1024).read_to_string(&mut s).is_ok()
                && s.contains("TargetMode=\"External\"")
            {
                rep.warnings.push(format!(
                    "External relationship in {r} (remote template or linked resource)."
                ));
            }
        }
    }
    // Media inside Office docs often carries its own EXIF.
    let media: Vec<String> = names
        .iter()
        .filter(|n| n.contains("/media/") && (n.ends_with(".jpg") || n.ends_with(".jpeg")))
        .take(10)
        .cloned()
        .collect();
    for m in media {
        if let Ok(mut f) = z.by_name(&m) {
            let mut buf = Vec::new();
            if f.by_ref()
                .take(20 * 1024 * 1024)
                .read_to_end(&mut buf)
                .is_ok()
            {
                let mut sub = FileReport::default();
                exif_fields(&buf, &mut sub);
                for mut fld in sub.fields {
                    fld.group = format!("Embedded {}", m.rsplit('/').next().unwrap_or(&m));
                    rep.fields.push(fld);
                }
                if let Some(g) = sub.gps {
                    rep.warnings.push(format!(
                        "Embedded image {m} has GPS coordinates ({:.5}, {:.5}).",
                        g.lat, g.lon
                    ));
                }
            }
        }
    }
}

// ---------------------------------------------------------------- strings

fn printable_strings(bytes: &[u8], min: usize, cap: usize) -> String {
    let mut out = String::new();
    let mut cur = Vec::new();
    for &b in bytes {
        if (0x20..0x7f).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= min {
                out.push_str(&String::from_utf8_lossy(&cur));
                out.push('\n');
                if out.len() > cap {
                    break;
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min {
        out.push_str(&String::from_utf8_lossy(&cur));
    }
    out
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    if hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

// ---------------------------------------------------------------- scrubbing

/// Remove metadata from JPEG (APP1–APP15 except ICC colour profile, COM)
/// and PNG (text, EXIF and time chunks) without re-encoding pixels.
/// Returns None for unsupported formats or malformed input.
pub fn strip(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.starts_with(b"\xFF\xD8") {
        let mut out = vec![0xFF, 0xD8];
        let mut i = 2;
        while i + 4 <= bytes.len() {
            if bytes[i] != 0xFF {
                return None;
            }
            let marker = bytes[i + 1];
            if marker == 0xFF {
                i += 1;
                continue;
            }
            if marker == 0xDA {
                // Start of scan: the rest is image data.
                out.extend_from_slice(&bytes[i..]);
                return Some(out);
            }
            let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
            let end = i + 2 + len;
            if end > bytes.len() {
                return None;
            }
            let seg = &bytes[i..end];
            let is_icc = marker == 0xE2 && seg.len() > 15 && &seg[4..15] == b"ICC_PROFILE";
            let drop = ((0xE1..=0xEF).contains(&marker) && !is_icc) || marker == 0xFE;
            if !drop {
                out.extend_from_slice(seg);
            }
            i = end;
        }
        None
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        let mut out = bytes[..8].to_vec();
        let mut i = 8;
        while i + 12 <= bytes.len() {
            let len =
                u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
            let end = i + 12 + len;
            if end > bytes.len() {
                return None;
            }
            let ty = &bytes[i + 4..i + 8];
            let drop = matches!(ty, b"tEXt" | b"iTXt" | b"zTXt" | b"eXIf" | b"tIME");
            if !drop {
                out.extend_from_slice(&bytes[i..end]);
            }
            if ty == b"IEND" {
                return Some(out);
            }
            i = end;
        }
        None
    } else {
        None
    }
}

// ---------------------------------------------------------------- entry

pub fn analyze(bytes: &[u8], name: &str) -> FileReport {
    let (label, mime, exts) = sniff(bytes);
    let ext = ext_of(name);
    let mut rep = FileReport {
        name: name.to_string(),
        size: bytes.len(),
        detected_type: label.to_string(),
        mime: mime.to_string(),
        entropy: (entropy(bytes) * 1000.0).round() / 1000.0,
        hashes: hashes(bytes),
        ..Default::default()
    };
    rep.extension_mismatch = !exts.is_empty() && !ext.is_empty() && !exts.contains(&ext.as_str());
    if rep.extension_mismatch {
        rep.warnings.push(format!(
            "Extension “.{ext}” doesn't match the content ({label}). Files disguised this way are a classic malware trick."
        ));
    }
    if (label.contains("executable"))
        && !["exe", "dll", "sys", "so", "dylib", "bin", "elf", ""].contains(&ext.as_str())
    {
        rep.warnings.push("This is an executable program.".into());
    }
    if rep.entropy > 7.5
        && !mime.starts_with("image/")
        && !mime.starts_with("video/")
        && !mime.contains("zip")
        && !mime.contains("compressed")
        && !mime.contains("gzip")
        && !mime.contains("rar")
        && !mime.contains("pdf")
        && !mime.contains("audio")
    {
        rep.warnings.push(format!(
            "Very high entropy ({:.2} bits/byte) — content is likely packed or encrypted.",
            rep.entropy
        ));
    }

    if mime.starts_with("image/") || mime.starts_with("video/") {
        exif_fields(bytes, &mut rep);
    }
    if mime == "application/pdf" {
        pdf_fields(bytes, &mut rep);
    }
    if mime == "application/zip" {
        zip_fields(bytes, &mut rep);
    }
    xmp_fields(bytes, &mut rep);

    // Indicators hidden in strings (skip for big media where it's noise).
    let scan_strings =
        !(mime.starts_with("image/") || mime.starts_with("video/") || mime.starts_with("audio/"));
    if scan_strings {
        let text = if mime == "text/plain" {
            String::from_utf8_lossy(&bytes[..bytes.len().min(4 * 1024 * 1024)]).into_owned()
        } else {
            printable_strings(bytes, 6, 4 * 1024 * 1024)
        };
        let mut iocs = crate::ioc::extract(&text);
        // Drop the noise every Office/PDF file carries (schema namespaces).
        let noisy = [
            "schemas.openxmlformats.org",
            "schemas.microsoft.com",
            "www.w3.org",
            "purl.org",
            "ns.adobe.com",
            "openoffice.org",
            "oasis-open.org",
            "iptc.org",
            "aiim.org",
        ];
        iocs.urls.retain(|u| !noisy.iter().any(|n| u.contains(n)));
        iocs.domains
            .retain(|d| !noisy.iter().any(|n| d.ends_with(n)) && d.contains('.') && d.len() > 4);
        iocs.total = iocs.urls.len()
            + iocs.domains.len()
            + iocs.ipv4.len()
            + iocs.ipv6.len()
            + iocs.emails.len()
            + iocs.md5.len()
            + iocs.sha1.len()
            + iocs.sha256.len()
            + iocs.cves.len();
        rep.iocs = iocs;
    }

    rep.warnings.sort();
    rep.warnings.dedup();
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_vector() {
        let h = hashes(b"abc");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            h.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[0u8; 100]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn mismatch_detected() {
        let r = analyze(b"MZ\x90\x00 this is a fake pe", "invoice.pdf");
        assert!(r.extension_mismatch);
        assert!(r.warnings.iter().any(|w| w.contains("doesn't match")));
    }

    #[test]
    fn pdf_info() {
        let pdf = b"%PDF-1.4\n1 0 obj\n<< /Title (Quarterly \\(Q3\\) report) /Author <FEFF004A006F0065> /Producer (Acrobat) /CreationDate (D:20230401123000+03'00') >>\nendobj\n%%EOF\nupdate\n%%EOF\n/OpenAction";
        let r = analyze(pdf, "r.pdf");
        let get = |k: &str| {
            r.fields
                .iter()
                .find(|f| f.key == k)
                .map(|f| f.value.clone())
        };
        assert_eq!(get("Title").as_deref(), Some("Quarterly (Q3) report"));
        assert_eq!(get("Author").as_deref(), Some("Joe"));
        assert_eq!(
            get("CreationDate").as_deref(),
            Some("2023-04-01 12:30:00 +03:00")
        );
        assert_eq!(get("Incremental saves").as_deref(), Some("1"));
        assert!(r.warnings.iter().any(|w| w.contains("OpenAction")));
    }

    #[test]
    fn docx_props() {
        use std::io::Write;
        let mut buf = Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let o: zip::write::SimpleFileOptions = Default::default();
            z.start_file("word/document.xml", o).unwrap();
            z.write_all(b"<w:document/>").unwrap();
            z.start_file("docProps/core.xml", o).unwrap();
            z.write_all(br#"<cp:coreProperties><dc:creator>Jane Analyst</dc:creator><cp:lastModifiedBy>J. Doe</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2024-02-01T10:00:00Z</dcterms:created></cp:coreProperties>"#).unwrap();
            z.start_file("docProps/app.xml", o).unwrap();
            z.write_all(
                b"<Properties><Application>Microsoft Office Word</Application></Properties>",
            )
            .unwrap();
            z.start_file("word/vbaProject.bin", o).unwrap();
            z.write_all(b"x").unwrap();
            z.finish().unwrap();
        }
        let r = analyze(buf.get_ref(), "memo.docx");
        assert_eq!(r.detected_type, "Word document (.docx)");
        assert!(!r.extension_mismatch);
        let get = |k: &str| {
            r.fields
                .iter()
                .find(|f| f.key == k)
                .map(|f| f.value.clone())
        };
        assert_eq!(get("dc:creator").as_deref(), Some("Jane Analyst"));
        assert_eq!(get("cp:lastModifiedBy").as_deref(), Some("J. Doe"));
        assert_eq!(
            get("dcterms:created").as_deref(),
            Some("2024-02-01T10:00:00Z")
        );
        assert!(r.warnings.iter().any(|w| w.contains("VBA")));
    }

    #[test]
    fn strings_iocs() {
        let mut bin = vec![0u8, 1, 2, 3];
        bin.extend_from_slice(b"connect http://198.51.100.7/beacon now");
        bin.extend_from_slice(&[0, 0xff, 0xfe]);
        let r = analyze(&bin, "sample.bin");
        assert_eq!(r.iocs.urls, vec!["http://198.51.100.7/beacon"]);
        assert_eq!(r.iocs.ipv4, vec!["198.51.100.7"]);
    }
}
