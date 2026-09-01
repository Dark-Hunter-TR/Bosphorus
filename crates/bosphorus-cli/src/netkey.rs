//! Network fingerprint for the discovery-profile store (M8, option A):
//! `gateway IPv4 + subnet CIDR + primary DNS suffix`, hashed to a short hex
//! stem for the profile filename. Windows-only; falls back to `"nonet"` if the
//! IP Helper calls fail (persistence still works, just un-namespaced).

use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersInfo, GetBestInterface, GetNetworkParams, FIXED_INFO_W2KSP1, IP_ADAPTER_INFO,
};

/// Returns `(human, key)` — a readable description and the hashed file stem.
pub fn compute() -> (String, String) {
    match probe() {
        Some(human) => {
            let key = format!("{:016x}", fnv1a(human.as_bytes()));
            (human, key)
        }
        None => ("nonet".to_string(), "nonet".to_string()),
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Read a fixed-size C `CHAR` array as a Rust string (up to the first NUL).
fn c_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn probe() -> Option<String> {
    let (gw, ip, mask) = first_gateway_adapter()?;
    let prefix = mask_to_prefix(&mask)?;
    let net = apply_mask(&ip, &mask)?;
    let dns = primary_dns_suffix().unwrap_or_default();
    Some(format!("gw={gw};net={net}/{prefix};dns={dns}"))
}

/// Interface index Windows would actually route public traffic out of. Without
/// this we would happily fingerprint a Radmin/Hamachi/VPN virtual adapter that
/// merely happens to come first in the adapter list — and the NetKey (and with
/// it the whole saved sweep) would change every time that adapter toggles.
fn egress_if_index() -> Option<u32> {
    // 8.8.8.8 is byte-uniform, so host/network order is moot here.
    let dest = u32::from_ne_bytes([8, 8, 8, 8]);
    let mut idx: u32 = 0;
    // SAFETY: `idx` is a valid out-param for the duration of the call.
    if unsafe { GetBestInterface(dest, &mut idx) } != 0 {
        return None;
    }
    Some(idx)
}

/// (gateway, unicast ip, mask) as dotted-decimal strings. Prefers the adapter
/// carrying the default route; falls back to the first adapter with a non-zero
/// gateway if `GetBestInterface` is unavailable.
fn first_gateway_adapter() -> Option<(String, String, String)> {
    let want = egress_if_index();
    unsafe {
        let mut len: u32 = 0;
        // First call sizes the buffer.
        let _ = GetAdaptersInfo(None, &mut len);
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        let head = buf.as_mut_ptr() as *mut IP_ADAPTER_INFO;
        if GetAdaptersInfo(Some(head), &mut len) != 0 {
            return None;
        }

        let read = |a: &IP_ADAPTER_INFO| {
            let gw = c_str(bytes_of(&a.GatewayList.IpAddress.String));
            let ip = c_str(bytes_of(&a.IpAddressList.IpAddress.String));
            let mask = c_str(bytes_of(&a.IpAddressList.IpMask.String));
            (gw, ip, mask)
        };

        // Pass 1: the interface the default route actually uses.
        if let Some(want) = want {
            let mut node = head;
            while !node.is_null() {
                let a = &*node;
                if a.Index == want {
                    let (gw, ip, mask) = read(a);
                    if !gw.is_empty() && gw != "0.0.0.0" {
                        return Some((gw, ip, mask));
                    }
                }
                node = a.Next;
            }
        }

        // Pass 2: first adapter with any default gateway.
        let mut node = head;
        while !node.is_null() {
            let a = &*node;
            let (gw, ip, mask) = read(a);
            if !gw.is_empty() && gw != "0.0.0.0" {
                return Some((gw, ip, mask));
            }
            node = a.Next;
        }
        None
    }
}

fn primary_dns_suffix() -> Option<String> {
    unsafe {
        let mut len: u32 = 0;
        let _ = GetNetworkParams(None, &mut len);
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len as usize];
        let head = buf.as_mut_ptr() as *mut FIXED_INFO_W2KSP1;
        if GetNetworkParams(Some(head), &mut len).is_err() {
            return None;
        }
        let s = c_str(bytes_of(&(*head).DomainName));
        Some(s)
    }
}

/// View a `[i8; N]` / `[CHAR; N]` field as `&[u8]`.
fn bytes_of<T>(field: &[T]) -> &[u8] {
    // SAFETY: `T` here is always a 1-byte character type (i8 / CHAR newtype).
    unsafe { std::slice::from_raw_parts(field.as_ptr() as *const u8, field.len()) }
}

fn octets(s: &str) -> Option<[u8; 4]> {
    let mut it = s.split('.');
    let mut o = [0u8; 4];
    for slot in &mut o {
        *slot = it.next()?.parse().ok()?;
    }
    if it.next().is_some() {
        return None;
    }
    Some(o)
}

fn mask_to_prefix(mask: &str) -> Option<u32> {
    let o = octets(mask)?;
    let bits = u32::from_be_bytes(o);
    // Must be a contiguous run of 1s.
    if bits != 0 && (bits.leading_ones() + bits.trailing_zeros() != 32) {
        return None;
    }
    Some(bits.count_ones())
}

fn apply_mask(ip: &str, mask: &str) -> Option<String> {
    let (a, m) = (octets(ip)?, octets(mask)?);
    let n = [a[0] & m[0], a[1] & m[1], a[2] & m[2], a[3] & m[3]];
    Some(format!("{}.{}.{}.{}", n[0], n[1], n[2], n[3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_and_network_math() {
        assert_eq!(mask_to_prefix("255.255.255.0"), Some(24));
        assert_eq!(mask_to_prefix("255.255.240.0"), Some(20));
        assert_eq!(mask_to_prefix("0.0.0.0"), Some(0));
        assert_eq!(mask_to_prefix("255.0.255.0"), None); // non-contiguous
        assert_eq!(apply_mask("192.168.1.37", "255.255.255.0").as_deref(), Some("192.168.1.0"));
    }

    #[test]
    fn compute_never_panics_and_key_is_stable() {
        let (_h1, k1) = compute();
        let (_h2, k2) = compute();
        assert_eq!(k1, k2);
        assert!(!k1.is_empty());
    }
}
