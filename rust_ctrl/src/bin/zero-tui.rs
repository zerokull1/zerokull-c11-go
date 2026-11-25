use std::env;
use std::ffi::c_int;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SHM_MAGIC: u64 = 0x5A45524F4B554C4C;
const SIGHUP: c_int = 1;

extern "C" {
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn isatty(fd: c_int) -> c_int;
    fn tcgetattr(fd: c_int, termios_p: *mut [u8; 64]) -> c_int;
    fn tcsetattr(fd: c_int, optional_actions: c_int, termios_p: *const [u8; 64]) -> c_int;
}

struct TtyGuard {
    orig: Option<[u8; 64]>,
}

impl TtyGuard {
    fn enter() -> Self {
        unsafe {
            if isatty(0) != 1 {
                return Self { orig: None };
            }
            let mut orig = [0u8; 64];
            if tcgetattr(0, &mut orig) != 0 {
                return Self { orig: None };
            }
            let mut raw = orig;
            let lflag = u32::from_ne_bytes(raw[12..16].try_into().unwrap_or([0; 4]));
            raw[12..16].copy_from_slice(&(lflag & !(0x0002 | 0x0008)).to_ne_bytes());
            raw[17 + 6] = 0; // VMIN = 0
            raw[17 + 5] = 0; // VTIME = 0
            if tcsetattr(0, 2, &raw) == 0 {
                print!("\x1b[?25l");
                let _ = io::stdout().flush();
                return Self { orig: Some(orig) };
            }
            Self { orig: None }
        }
    }
}

impl Drop for TtyGuard {
    fn drop(&mut self) {
        if let Some(ref orig) = self.orig {
            unsafe {
                tcsetattr(0, 2, orig);
            }
        }
        println!("\x1b[?25h\x1b[0m");
        let _ = io::stdout().flush();
    }
}

#[derive(Default, Clone, Copy)]
struct Telemetry {
    valid: bool,
    pid: u32,
    start_ts: u64,
    inspected: u64,
    drops: u64,
    bans: u64,
    shadow_mode: u32,
}

fn read_shm(shm_path: &str) -> Telemetry {
    let Ok(buf) = fs::read(shm_path) else {
        return Telemetry::default();
    };
    if buf.len() < 48 {
        return Telemetry::default();
    }
    let magic = u64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
    if magic != SHM_MAGIC {
        return Telemetry::default();
    }
    Telemetry {
        valid: true,
        pid: u32::from_le_bytes(buf[12..16].try_into().unwrap_or([0; 4])),
        start_ts: u64::from_le_bytes(buf[16..24].try_into().unwrap_or([0; 8])),
        inspected: u64::from_le_bytes(buf[24..32].try_into().unwrap_or([0; 8])),
        drops: u64::from_le_bytes(buf[32..40].try_into().unwrap_or([0; 8])),
        bans: u64::from_le_bytes(buf[40..48].try_into().unwrap_or([0; 8])),
        shadow_mode: if buf.len() >= 48 {
            u32::from_le_bytes(buf[44..48].try_into().unwrap_or([0; 4]))
        } else {
            0
        },
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let shm_name = args.get(1).map(String::as_str).unwrap_or("/zerokull_stats");
    let once = args.get(2).map(String::as_str) == Some("--once");
    let shm_fs = format!("/dev/shm/{}", shm_name.trim_start_matches('/'));

    let _tty = TtyGuard::enter();
    let mut prev: Option<(u64, u64)> = None;
    let mut status = String::from("READY (keys: [R] reload policy SIGHUP | [Q] quit)");

    loop {
        let t = read_shm(&shm_fs);
        let active = t.valid && t.pid > 0 && Path::new(&format!("/proc/{}", t.pid)).exists();
        let (pps, dps) = match prev {
            Some((pi, pd)) if t.valid && t.inspected >= pi && t.drops >= pd => {
                ((t.inspected - pi) * 5, (t.drops - pd) * 5)
            }
            _ => (0, 0),
        };
        if t.valid {
            prev = Some((t.inspected, t.drops));
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let up = if active && now >= t.start_ts { now - t.start_ts } else { 0 };
        let drop_pct = if t.valid && t.inspected > 0 {
            ((t.drops * 100) / t.inspected).min(100)
        } else {
            0
        };
        let filled = ((drop_pct * 30) / 100) as usize;
        let bar = format!("{}{}", "#".repeat(filled), ".".repeat(30 - filled));

        print!("\x1b[H\x1b[2J");
        println!("\x1b[1;36m+----------------------------------------------------------------------+\x1b[0m");
        println!("\x1b[1;36m| ZEROKULL SSH OPERATOR RADAR (zero-tui | Safe Rust Headless Console)  |\x1b[0m");
        println!("\x1b[1;36m+----------------------------------------------------------------------+\x1b[0m");
        println!(
            "| State : {}{:<12}\x1b[0m | PID: {:<8} | Uptime: {:<10}s |",
            if active { "\x1b[1;32m" } else { "\x1b[1;31m" },
            if active { "ACTIVE" } else { "OFFLINE" },
            t.pid,
            up
        );
        println!(
            "| Mode  : {:<12} | SHM: {:<36} |",
            if t.valid && t.shadow_mode != 0 { "SHADOW_AUDIT" } else { "XDP_ENFORCE" },
            shm_name
        );
        println!("+----------------------------------------------------------------------+");
        println!("| Inspected Total : {:<18} | Rate : {:<12} pps |", t.inspected, pps);
        println!("| Dropped Total   : {:<18} | Rate : {:<12} pps |", t.drops, dps);
        println!("| Auto-Banned IPs : {:<18} | Drop Ratio : {:>3}%          |", t.bans, drop_pct);
        println!("| Mitigation Load : [\x1b[1;33m{}\x1b[0m]                  |", bar);
        println!("+----------------------------------------------------------------------+");
        println!("| {:<68} |", status);
        println!("+----------------------------------------------------------------------+");
        let _ = io::stdout().flush();

        if once {
            break;
        }

        let mut key = [0u8; 1];
        if io::stdin().read(&mut key).unwrap_or(0) == 1 {
            match key[0] {
                b'q' | b'Q' => break,
                b'r' | b'R' => {
                    if active && unsafe { kill(t.pid as c_int, SIGHUP) } == 0 {
                        status = format!("SIGHUP SENT -> PID {} reloaded /etc/zeromani/policy.conf", t.pid);
                    } else {
                        status = String::from("WARN: daemon offline or EPERM sending SIGHUP");
                    }
                }
                _ => {}
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
}
