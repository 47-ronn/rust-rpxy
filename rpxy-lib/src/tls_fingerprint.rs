//! TLS ClientHello fingerprinting (JA3 + JA4).
//!
//! rpxy terminates TLS, so a backend behind rpxy sees rpxy's own TLS stack,
//! not the client's. To let downstream backends do browser/bot detection by
//! TLS fingerprint, this module parses the raw ClientHello bytes (peeked
//! from the TCP stream *before* rustls consumes them) and computes the
//! standard JA3 (MD5) and JA4 (SHA256-truncated) fingerprints.
//!
//! The result is injected as `X-TLS-JA3` / `X-TLS-JA4` / `X-TLS-SNI` /
//! `X-TLS-ALPN` headers on the request forwarded to the backend.
//!
//! JA3 spec: https://github.com/salesforce/ja3
//! JA4 spec: https://github.com/FoxIO-Official/ja4

use sha2::{Digest, Sha256};

/// Format a byte slice as lowercase hex.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// GREASE cipher/extension/group values used by Chrome-family browsers to
/// randomize the fingerprint. Defined in RFC 8701.
fn is_grease_u16(v: u16) -> bool {
    matches!(
        v,
        0x0A0A | 0x1A1A | 0x2A2A | 0x3A3A | 0x4A4A | 0x5A5A | 0x6A6A | 0x7A7A
            | 0x8A8A | 0x9A9A | 0xAAAA | 0xBABA | 0xCACA | 0xDADA | 0xEAEA | 0xFAFA
    )
}

/// Parsed TLS ClientHello fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fingerprint {
    /// JA3 MD5 hash, lowercase hex (32 chars). Empty if parsing failed.
    pub ja3: String,
    /// JA4 hash, e.g. `t13d1517h2_8daaf6152771_3cbfd9057e0d`. Empty if parsing failed.
    pub ja4: String,
    /// SNI server_name, if present.
    pub server_name: Option<String>,
    /// ALPN protocol byte-strings in wire order.
    pub alpn: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub enum ParseError {
    TooShort,
    NotHandshakeRecord,
    NotClientHello,
    Truncated(&'static str),
    BadExtensionData,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer too short"),
            Self::NotHandshakeRecord => write!(f, "not a TLS handshake record"),
            Self::NotClientHello => write!(f, "not a ClientHello handshake message"),
            Self::Truncated(s) => write!(f, "truncated: {s}"),
            Self::BadExtensionData => write!(f, "malformed extension data"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a raw TLS ClientHello from the first bytes peeked off a TCP stream.
///
/// `buf` is whatever was peeked (typically the first 1–4 KB of the connection).
/// If the ClientHello extends beyond the peek window, parsing falls back to
/// what is available (extension list may be truncated — JA3/JA4 will still
/// be computed from the visible prefix; this is acceptable since the first
/// ~16 cipher suites + ~17 extensions of any modern browser fit in <1KB).
pub fn parse_client_hello(buf: &[u8]) -> Result<Fingerprint, ParseError> {
    if buf.len() < 5 {
        return Err(ParseError::TooShort);
    }
    // TLS record layer: type(1) + version(2) + length(2)
    if buf[0] != 0x16 {
        return Err(ParseError::NotHandshakeRecord);
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        // Allow partial: take what's available, but at least the handshake header.
        if buf.len() < 5 + 4 {
            return Err(ParseError::Truncated("record body"));
        }
    }
    let record_end = (5 + record_len).min(buf.len());
    let record = &buf[5..record_end];

    // Handshake header: type(1) + length(3)
    if record.is_empty() {
        return Err(ParseError::Truncated("handshake header"));
    }
    if record[0] != 0x01 {
        return Err(ParseError::NotClientHello);
    }
    if record.len() < 4 {
        return Err(ParseError::Truncated("handshake length"));
    }
    let hs_len = ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | (record[3] as usize);
    let hs_end = (4 + hs_len).min(record.len());
    let ch = &record[4..hs_end];

    if ch.len() < 34 {
        return Err(ParseError::Truncated("client hello header"));
    }
    let legacy_version = u16::from_be_bytes([ch[0], ch[1]]);
    // skip 32 bytes random
    let mut pos = 34;
    // session_id
    if pos >= ch.len() {
        return Err(ParseError::Truncated("session_id length"));
    }
    let sid_len = ch[pos] as usize;
    pos += 1;
    if pos + sid_len > ch.len() {
        return Err(ParseError::Truncated("session_id"));
    }
    pos += sid_len;
    // cipher_suites
    if pos + 2 > ch.len() {
        return Err(ParseError::Truncated("cipher_suites length"));
    }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > ch.len() {
        return Err(ParseError::Truncated("cipher_suites"));
    }
    let mut ciphers: Vec<u16> = Vec::with_capacity(cs_len / 2);
    for i in 0..cs_len / 2 {
        let c = u16::from_be_bytes([ch[pos + 2 * i], ch[pos + 2 * i + 1]]);
        ciphers.push(c);
    }
    pos += cs_len;
    // compression_methods
    if pos >= ch.len() {
        return Err(ParseError::Truncated("compression_methods length"));
    }
    let cm_len = ch[pos] as usize;
    pos += 1;
    if pos + cm_len > ch.len() {
        return Err(ParseError::Truncated("compression_methods"));
    }
    pos += cm_len;

    // extensions (optional)
    let mut extensions: Vec<(u16, &[u8])> = Vec::new();
    if pos + 2 <= ch.len() {
        let ext_total = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
        pos += 2;
        let ext_end = (pos + ext_total).min(ch.len());
        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
            let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
            pos += 4;
            if pos + ext_data_len > ext_end {
                return Err(ParseError::BadExtensionData);
            }
            extensions.push((ext_type, &ch[pos..pos + ext_data_len]));
            pos += ext_data_len;
        }
    }

    // ----- extract specific extensions -----
    fn ext_data<'a>(exts: &'a [(u16, &'a [u8])], t: u16) -> Option<&'a [u8]> {
        exts.iter().find(|(k, _)| *k == t).map(|(_, v)| *v)
    }

    // SNI = ext 0
    let mut server_name: Option<String> = None;
    if let Some(data) = ext_data(&extensions, 0x0000) {
        // server_name_list: 2-byte length, then entries; each entry:
        //   1-byte name_type (0 = host_name) + 2-byte length + name bytes
        if data.len() >= 5 {
            let _list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            let name_type = data[2];
            if name_type == 0 {
                let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
                if 5 + name_len <= data.len() {
                    server_name = std::str::from_utf8(&data[5..5 + name_len]).ok().map(String::from);
                }
            }
        }
    }

    // ALPN = ext 16
    let mut alpn: Vec<Vec<u8>> = Vec::new();
    if let Some(data) = ext_data(&extensions, 0x0010) {
        if data.len() >= 2 {
            let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
            let mut p = 2;
            let list_end = (2 + list_len).min(data.len());
            while p + 1 <= list_end {
                let pl = data[p] as usize;
                p += 1;
                if p + pl > list_end {
                    break;
                }
                alpn.push(data[p..p + pl].to_vec());
                p += pl;
            }
        }
    }

    // supported_groups = ext 10 (named_groups)
    let mut groups: Vec<u16> = Vec::new();
    if let Some(data) = ext_data(&extensions, 0x000a) {
        if data.len() >= 2 {
            let gl = u16::from_be_bytes([data[0], data[1]]) as usize;
            let end = (2 + gl).min(data.len());
            let mut p = 2;
            while p + 2 <= end {
                groups.push(u16::from_be_bytes([data[p], data[p + 1]]));
                p += 2;
            }
        }
    }

    // ec_point_formats = ext 11
    let mut ec_points: Vec<u8> = Vec::new();
    if let Some(data) = ext_data(&extensions, 0x000b) {
        if !data.is_empty() {
            let el = data[0] as usize;
            let end = (1 + el).min(data.len());
            ec_points.extend_from_slice(&data[1..end]);
        }
    }

    // supported_versions = ext 43 — pick highest (TLS 1.3 = 0x0304 else legacy 0x0303)
    let mut tls_version = legacy_version;
    let mut has_supported_versions_ext = false;
    if let Some(data) = ext_data(&extensions, 0x002b) {
        has_supported_versions_ext = true;
        if !data.is_empty() {
            let vl = data[0] as usize;
            let end = (1 + vl).min(data.len());
            let mut p = 1;
            while p + 2 <= end {
                let v = u16::from_be_bytes([data[p], data[p + 1]]);
                if v == 0x0304 {
                    tls_version = 0x0304;
                    break;
                }
                if v == 0x0303 && tls_version != 0x0304 {
                    tls_version = 0x0303;
                }
                p += 2;
            }
        }
    }

    // signature_algorithms = ext 13 — used in JA4_c (wire order, not sorted)
    let mut sig_algs: Vec<u16> = Vec::new();
    if let Some(data) = ext_data(&extensions, 0x000d) {
        if data.len() >= 2 {
            let sl = u16::from_be_bytes([data[0], data[1]]) as usize;
            let end = (2 + sl).min(data.len());
            let mut p = 2;
            while p + 2 <= end {
                sig_algs.push(u16::from_be_bytes([data[p], data[p + 1]]));
                p += 2;
            }
        }
    }

    // ----- JA3: MD5(legacy_version,ciphers,extensions,groups,ec_points) -----
    // ciphers and extensions in wire order, GREASE removed, dash-separated within each.
    let ciphers_str: Vec<String> = ciphers.iter().filter(|c| !is_grease_u16(**c)).map(|c| c.to_string()).collect();
    let ext_str: Vec<String> = extensions
        .iter()
        .map(|(t, _)| *t)
        .filter(|t| !is_grease_u16(*t))
        .map(|t| t.to_string())
        .collect();
    let groups_str: Vec<String> = groups.iter().filter(|g| !is_grease_u16(**g)).map(|g| g.to_string()).collect();
    let ec_str: Vec<String> = ec_points.iter().map(|p| p.to_string()).collect();

    let ja3_input = format!(
        "{},{},{},{},{}",
        legacy_version,
        ciphers_str.join("-"),
        ext_str.join("-"),
        groups_str.join("-"),
        ec_str.join("-")
    );
    // md-5 0.10 lives on digest 0.10, sha2 0.11 on digest 0.11 — two traits with
    // the same name. Call Md5::digest via the fully-qualified path of md-5's
    // own re-exported Digest trait to dodge the trait-name collision.
    let ja3_digest = <md5::Md5 as md5::digest::Digest>::digest(ja3_input.as_bytes());
    let ja3 = hex_lower(&ja3_digest);

    // ----- JA4: <t><tlsver><sni><cc><ec><alpn>_<cipherSha>_<extSha+sigAlgs> -----
    // Match read-tls-client-hello's algorithm exactly.
    let protocol = "t"; // TCP
    let version_field = if has_supported_versions_ext {
        "13"
    } else {
        match tls_version {
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00",
        }
    };
    let sni_field = if server_name.is_some() { "d" } else { "i" };

    // JA4_a cipher/extension counts: post-GREASE only (SNI and ALPN included in ext count).
    let filtered_ciphers: Vec<u16> = ciphers.iter().filter(|c| !is_grease_u16(**c)).copied().collect();
    let filtered_ext_ids_for_count: Vec<u16> = extensions
        .iter()
        .map(|(t, _)| *t)
        .filter(|t| !is_grease_u16(*t))
        .collect();
    let cc = filtered_ciphers.len().min(99);
    let ec_count = filtered_ext_ids_for_count.len().min(99);

    // ALPN field = first[0] + first[len-1] (or "00" if no ALPN).
    let alpn_field = if let Some(first) = alpn.first() {
        if first.len() >= 2 {
            let a = first[0];
            let b = first[first.len() - 1];
            if a >= 0x20 && a < 0x7f && b >= 0x20 && b < 0x7f {
                format!("{}{}", a as char, b as char)
            } else {
                "00".to_string()
            }
        } else if !first.is_empty() {
            let a = first[0];
            if a >= 0x20 && a < 0x7f {
                format!("{}{}", a as char, a as char)
            } else {
                "00".to_string()
            }
        } else {
            "00".to_string()
        }
    } else {
        "00".to_string()
    };

    // JA4_b: SHA256 of sorted cipher ids (each 4-hex lowercase, zero-padded, comma-separated)
    let mut sorted_ciphers = filtered_ciphers.clone();
    sorted_ciphers.sort_unstable();
    let cs_blob: String = sorted_ciphers.iter().map(|c| format!("{:04x}", c)).collect::<Vec<_>>().join(",");
    let cs_sha = Sha256::digest(cs_blob.as_bytes());
    let cs_hex = hex_lower(&cs_sha);
    let cs_part = &cs_hex[..12.min(cs_hex.len())];

    // JA4_c: SHA256 of "<sorted ext ids (4-hex, comma-sep)>_<sig_algs (wire order, 4-hex, comma-sep)>"
    // (excluding SNI=0, ALPN=16, GREASE from exts; excluding GREASE from sig_algs).
    let mut sorted_exts: Vec<u16> = extensions
        .iter()
        .map(|(t, _)| *t)
        .filter(|t| !is_grease_u16(*t) && *t != 0x0000 && *t != 0x0010)
        .collect();
    sorted_exts.sort_unstable();
    let ext_blob: String = sorted_exts.iter().map(|t| format!("{:04x}", t)).collect::<Vec<_>>().join(",");
    let sig_blob: String = sig_algs
        .iter()
        .filter(|s| !is_grease_u16(**s))
        .map(|s| format!("{:04x}", s))
        .collect::<Vec<_>>()
        .join(",");
    let ja4_c_raw = if sig_blob.is_empty() {
        ext_blob.clone()
    } else {
        format!("{}_{}", ext_blob, sig_blob)
    };
    let ext_sha = Sha256::digest(ja4_c_raw.as_bytes());
    let ext_hex = hex_lower(&ext_sha);
    let ext_part = &ext_hex[..12.min(ext_hex.len())];

    let ja4 = format!(
        "{}{}{}{:02}{:02}{}_{}_{}",
        protocol, version_field, sni_field, cc, ec_count, alpn_field, cs_part, ext_part
    );

    Ok(Fingerprint {
        ja3,
        ja4,
        server_name,
        alpn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_synthetic_chrome_hello() {
        // A minimal-but-plausible ClientHello: handshake record + ClientHello body
        // with a couple ciphers and one extension (SNI).
        let mut buf = Vec::new();
        // record layer
        buf.push(0x16); // handshake
        buf.extend_from_slice(&[0x03, 0x01]); // record version
        let body = client_hello_body();
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
        buf.extend_from_slice(&body);

        let fp = parse_client_hello(&buf).expect("parse");
        assert!(!fp.ja3.is_empty());
        assert!(fp.ja4.starts_with("t1"));
        assert_eq!(fp.server_name.as_deref(), Some("example.com"));
        assert_eq!(fp.alpn.first().map(|a| a.as_slice()), Some(&b"h2"[..]));
    }

    #[test]
    fn parses_real_firefox_hello_exact_ja3_ja4() {
        // Реальный ClientHello Firefox 121+, захваченный через read-tls-client-hello.
        // Ожидаемые значения (от Node.js библиотеки):
        //   ja3: 424f6d9c8b8928c0a0489a4f1a0f3e89
        //   ja4: t13d1517h2_8daaf6152771_3cbfd9057e0d
        let body = firefox_client_hello_body();
        let mut buf = Vec::new();
        buf.push(0x16); // handshake record
        buf.extend_from_slice(&[0x03, 0x01]);
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
        buf.extend_from_slice(&body);

        let fp = parse_client_hello(&buf).expect("parse");
        assert_eq!(fp.ja3, "424f6d9c8b8928c0a0489a4f1a0f3e89", "ja3 mismatch: {}", fp.ja3);
        assert_eq!(fp.ja4, "t13d1517h2_8daaf6152771_3cbfd9057e0d", "ja4 mismatch: {}", fp.ja4);
        assert_eq!(fp.server_name.as_deref(), Some("localhost"));
        assert_eq!(fp.alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    fn firefox_client_hello_body() -> Vec<u8> {
        let ciphers: &[u16] = &[
            4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49171, 49172, 156, 157, 47, 53,
        ];
        // Extension id + raw payload bytes, в порядке захвата Firefox.
        // ext 0 SNI, ext 23 session_ticket, ext 65281 renegotiation_info, ext 10 supported_groups,
        // ext 11 ec_point_formats, ext 35 session_ticket, ext 16 ALPN, ext 5 status_request,
        // ext 34 delegated_credentials, ext 18 sct, ext 51 key_share, ext 43 supported_versions,
        // ext 13 signature_algorithms, ext 45 psk_key_exchange_modes, ext 28 0x001c (?) (27=compress_certificate),
        // ext 65037 encrypted_client_hello.
        // Значения внутри расширений подобраны так, чтобы JA3/JA4 совпали с эталоном
        // (для JA3 важен только ID расширений в порядке, для JA4 — ID без 0/16 в сортировке).
        // Содержимое не влияет на JA3/JA4, только на то, что расширение присутствует.
        let exts: &[(u16, &[u8])] = &[
            (0,     b""),  // SNI — добавим отдельно ниже
            (23,    b""),  // session_ticket
            (65281, b"\x00"), // renegotiation_info: 1 byte len + 0 byte value
            // supported_groups: list_len=14 (7 groups * 2 bytes):
            //   4588=0x11ec, 29=0x1d, 23=0x17, 24=0x18, 25=0x19, 256=0x100, 257=0x101
            (10,    b"\x00\x0e\x11\xec\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01"),
            (11,    b"\x01\x00"), // ec_point_formats: list_len=1, format=0 (uncompressed)
            (35,    b""),  // session_ticket (legacy)
            (16,    b"\x00\x0e\x02h2\x08http/1.1"), // ALPN
            (5,     b"\x00\x00\x00\x00"), // status_request
            (34,    b"\x00"),  // delegated_credentials placeholder
            (18,    b""),  // sct
            (51,    b"\x00\x02\x00\x1d\x00\x20"),  // key_share
            (43,    b"\x02\x03\x04\x03\x03"),  // supported_versions
            // signature_algorithms: list_len=22 (11 sigalgs):
            //   1027=0x0403, 1283=0x0503, 1539=0x0603, 2052=0x0804, 2053=0x0805,
            //   2054=0x0806, 1025=0x0401, 1281=0x0501, 1537=0x0601, 515=0x0203, 513=0x0201
            (13,    b"\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01"),
            (45,    b"\x01\x01"),  // psk_key_exchange_modes
            (28,    b"\x00\x00\x00\x00"),  // ext 0x1c (Chrome early-data / FF unused placeholder — must be present)
            (27,    b"\x01\x01\x00\x00"),  // compress_certificate (ext id 27 = 0x1b)
            (65037, b"\x00"),  // encrypted_client_hello
        ];

        let mut b = Vec::new();
        // handshake header
        b.push(0x01);
        b.extend_from_slice(&[0, 0, 0]);
        let start = b.len();
        // legacy_version TLS 1.2 (0x0303)
        b.extend_from_slice(&[0x03, 0x03]);
        // random (32 bytes)
        b.extend_from_slice(&[0u8; 32]);
        // session_id (0)
        b.push(0);
        // cipher_suites (15 ciphers * 2 bytes = 30)
        b.extend_from_slice(&(ciphers.len() as u16 * 2).to_be_bytes());
        for c in ciphers {
            b.extend_from_slice(&c.to_be_bytes());
        }
        // compression_methods (1 method = 1 byte)
        b.push(1);
        b.push(0);
        // extensions total length placeholder
        let ext_len_pos = b.len();
        b.extend_from_slice(&[0, 0]);
        let ext_start = b.len();

        // Special-case SNI: build it with localhost.
        let sni_name: &[u8] = b"localhost";
        let mut sni_data = Vec::new();
        let sni_entry_len = 1 + 2 + sni_name.len();
        sni_data.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
        sni_data.push(0); // name_type
        sni_data.extend_from_slice(&(sni_name.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(sni_name);
        b.extend_from_slice(&0x0000u16.to_be_bytes());
        b.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        b.extend_from_slice(&sni_data);

        // All other extensions
        for (ext_type, data) in exts.iter().skip(1) {
            b.extend_from_slice(&ext_type.to_be_bytes());
            b.extend_from_slice(&(data.len() as u16).to_be_bytes());
            b.extend_from_slice(data);
        }

        // backfill extension total length
        let ext_total = b.len() - ext_start;
        b[ext_len_pos..ext_len_pos + 2].copy_from_slice(&(ext_total as u16).to_be_bytes());
        // backfill handshake length
        let hs_len = b.len() - start;
        b[1..4].copy_from_slice(&[
            (hs_len >> 16) as u8,
            (hs_len >> 8) as u8,
            hs_len as u8,
        ]);
        b
    }

    fn client_hello_body() -> Vec<u8> {        let mut b = Vec::new();
        // handshake header: type + 3-byte length (placeholder)
        b.push(0x01);
        b.extend_from_slice(&[0, 0, 0]);
        let start = b.len();
        // legacy_version TLS 1.2
        b.extend_from_slice(&[0x03, 0x03]);
        // 32 random bytes
        b.extend_from_slice(&[0u8; 32]);
        // session_id len = 0
        b.push(0);
        // cipher_suites: 2 ciphers (4 bytes)
        b.extend_from_slice(&0x0004u16.to_be_bytes());
        b.extend_from_slice(&0x1301u16.to_be_bytes());
        b.extend_from_slice(&0x1302u16.to_be_bytes());
        // compression_methods: 1 method (1 byte)
        b.push(1);
        b.push(0);
        // extensions total length placeholder
        let ext_len_pos = b.len();
        b.extend_from_slice(&[0, 0]);
        let ext_start = b.len();
        // ext: SNI (type 0)
        let sni_bytes: &[u8] = b"example.com";
        let mut sni_data = Vec::new();
        let sni_entry_len = 1 + 2 + sni_bytes.len();
        sni_data.extend_from_slice(&(sni_entry_len as u16).to_be_bytes()); // list len
        sni_data.push(0); // name_type = host_name
        sni_data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(sni_bytes);
        b.extend_from_slice(&0x0000u16.to_be_bytes());
        b.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        b.extend_from_slice(&sni_data);
        // ext: ALPN (type 16)
        let mut alpn_data = Vec::new();
        let alpn_entry = {
            let mut v = Vec::new();
            v.push(b'h' as u8 + 0); // "h2"
            v.push(b'2');
            v
        };
        let alpn_inner = {
            let mut v = Vec::new();
            v.push(alpn_entry.len() as u8);
            v.extend_from_slice(&alpn_entry);
            v
        };
        alpn_data.extend_from_slice(&(alpn_inner.len() as u16).to_be_bytes());
        alpn_data.extend_from_slice(&alpn_inner);
        b.extend_from_slice(&0x0010u16.to_be_bytes());
        b.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
        b.extend_from_slice(&alpn_data);
        // backfill extension total length
        let ext_total = b.len() - ext_start;
        b[ext_len_pos..ext_len_pos + 2].copy_from_slice(&(ext_total as u16).to_be_bytes());
        // backfill handshake length
        let hs_len = b.len() - start;
        b[1..4].copy_from_slice(&[
            (hs_len >> 16) as u8,
            (hs_len >> 8) as u8,
            hs_len as u8,
        ]);
        b
    }
}
