use osint_toolkit::meta;

const GEO: &[u8] = include_bytes!("fixtures/geo.jpg");

#[test]
fn reads_gps_from_jpeg() {
    let r = meta::analyze(GEO, "geo.jpg");
    let g = r.gps.expect("gps");
    assert!((g.lat - 33.8938).abs() < 1e-4);
    assert!((g.lon - 35.5018).abs() < 1e-4);
    assert!(r
        .fields
        .iter()
        .any(|f| f.key == "Model" && f.value == "EOS R6"));
}

#[test]
fn strips_jpeg_metadata() {
    let clean = meta::strip(GEO).expect("supported");
    assert!(clean.len() < GEO.len());
    let r = meta::analyze(&clean, "geo.jpg");
    assert!(r.gps.is_none());
    assert!(r.fields.is_empty());
    assert_eq!(r.detected_type, "JPEG image");
}

#[test]
fn strip_unsupported() {
    assert!(meta::strip(b"%PDF-1.4").is_none());
}
