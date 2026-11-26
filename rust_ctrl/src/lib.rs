// ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
use std::ffi::{c_int, c_void, CStr};
use std::fs;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::os::raw::c_char;

pub const ZK_POLICY_MAX_IPS: usize = 256;

#[repr(C)]
pub struct ZkPolicyCfg {
    pub loaded: bool,
    pub has_mode: bool,
    pub shadow_mode: bool,
    pub cpu_affinity: c_int,
    pub allow_ips: [u32; ZK_POLICY_MAX_IPS],
    pub allow_cnt: u32,
    pub deny_ips: [u32; ZK_POLICY_MAX_IPS],
    pub deny_cnt: u32,
}

extern "C" {
    fn bpf_map_update_elem(fd: c_int, key: *const c_void, value: *const c_void, flags: u64) -> c_int;
    fn bpf_map_delete_elem(fd: c_int, key: *const c_void) -> c_int;
    fn sched_setaffinity(pid: c_int, cpusetsize: usize, mask: *const u8) -> c_int;
}

fn parse_policy_str(content: &str, out: &mut ZkPolicyCfg) {
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (key, val) = (k.trim(), v.trim());

        match key {
            "mode" => {
                out.has_mode = true;
                out.shadow_mode = matches!(val, "shadow" | "dry-run");
            }
            "cpu_affinity" => {
                if let Ok(cpu) = val.parse::<i32>() {
                    if (0..1024).contains(&cpu) {
                        out.cpu_affinity = cpu;
                    }
                }
            }
            "allow_ip" => {
                if let Ok(ip) = val.parse::<Ipv4Addr>() {
                    let net_ip = u32::from_ne_bytes(ip.octets());
                    let cnt = out.allow_cnt as usize;
                    if cnt < ZK_POLICY_MAX_IPS && !out.allow_ips[..cnt].contains(&net_ip) {
                        out.allow_ips[cnt] = net_ip;
                        out.allow_cnt += 1;
                    }
                }
            }
            "deny_ip" => {
                if let Ok(ip) = val.parse::<Ipv4Addr>() {
                    let net_ip = u32::from_ne_bytes(ip.octets());
                    let cnt = out.deny_cnt as usize;
                    if cnt < ZK_POLICY_MAX_IPS && !out.deny_ips[..cnt].contains(&net_ip) {
                        out.deny_ips[cnt] = net_ip;
                        out.deny_cnt += 1;
                    }
                }
            }
            _ => {}
        }
    }
    out.loaded = true;
}

#[no_mangle]
pub unsafe extern "C" fn zk_policy_load(path: *const c_char, out: *mut ZkPolicyCfg) -> c_int {
    let Some(out_ref) = out.as_mut() else { return -1 };
    *out_ref = ZkPolicyCfg {
        loaded: false, has_mode: false, shadow_mode: false, cpu_affinity: -1,
        allow_ips: [0; ZK_POLICY_MAX_IPS], allow_cnt: 0,
        deny_ips: [0; ZK_POLICY_MAX_IPS], deny_cnt: 0,
    };
    if path.is_null() {
        return -1;
    }
    let Ok(path_str) = CStr::from_ptr(path).to_str() else { return -1 };
    if path_str.is_empty() {
        return -1;
    }
    match fs::read_to_string(path_str) {
        Ok(text) => {
            parse_policy_str(&text, out_ref);
            0
        }
        Err(e) if e.kind() == ErrorKind::NotFound => 0,
        Err(_) => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn zk_policy_apply_bpf(
    prev: *const ZkPolicyCfg,
    cur: *const ZkPolicyCfg,
    whitelist_fd: c_int,
    blacklist_fd: c_int,
) {
    let Some(c) = cur.as_ref() else { return };
    let cur_allow = &c.allow_ips[..(c.allow_cnt as usize).min(ZK_POLICY_MAX_IPS)];
    let cur_deny = &c.deny_ips[..(c.deny_cnt as usize).min(ZK_POLICY_MAX_IPS)];
    let one: u8 = 1;

    if let Some(p) = prev.as_ref().filter(|p| p.loaded) {
        for &ip in &p.allow_ips[..(p.allow_cnt as usize).min(ZK_POLICY_MAX_IPS)] {
            if !cur_allow.contains(&ip) {
                bpf_map_delete_elem(whitelist_fd, (&ip as *const u32).cast());
            }
        }
        for &ip in &p.deny_ips[..(p.deny_cnt as usize).min(ZK_POLICY_MAX_IPS)] {
            if !cur_deny.contains(&ip) {
                bpf_map_delete_elem(blacklist_fd, (&ip as *const u32).cast());
            }
        }
    }
    for &ip in cur_allow {
        bpf_map_update_elem(whitelist_fd, (&ip as *const u32).cast(), (&one as *const u8).cast(), 0);
        bpf_map_delete_elem(blacklist_fd, (&ip as *const u32).cast());
    }
    for &ip in cur_deny {
        bpf_map_update_elem(blacklist_fd, (&ip as *const u32).cast(), (&one as *const u8).cast(), 0);
        bpf_map_delete_elem(whitelist_fd, (&ip as *const u32).cast());
    }
}

#[no_mangle]
pub unsafe extern "C" fn zk_policy_apply_affinity(cpu_id: c_int) {
    if !(0..1024).contains(&cpu_id) {
        return;
    }
    let mut mask = [0u8; 128];
    let idx = (cpu_id as usize) / 8;
    let bit = (cpu_id as usize) % 8;
    mask[idx] |= 1u8 << bit;
    sched_setaffinity(0, mask.len(), mask.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_policy() {
        let mut cfg = ZkPolicyCfg {
            loaded: false, has_mode: false, shadow_mode: false, cpu_affinity: -1,
            allow_ips: [0; 256], allow_cnt: 0, deny_ips: [0; 256], deny_cnt: 0,
        };
        parse_policy_str("# cmt\nmode = shadow\ncpu_affinity = 3\nallow_ip = 10.0.0.1\ndeny_ip = 192.0.2.5\n", &mut cfg);
        assert!(cfg.loaded && cfg.has_mode && cfg.shadow_mode && cfg.cpu_affinity == 3);
        assert_eq!(cfg.allow_cnt, 1);
        assert_eq!(cfg.deny_cnt, 1);
    }
}
