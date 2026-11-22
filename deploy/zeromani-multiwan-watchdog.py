#!/usr/bin/env python3
import re, subprocess, time

TARGETS = ["77.88.8.8", "9.9.9.9"]

def get_gateways():
    out = subprocess.check_output(["ip", "-4", "route", "show", "default"], text=True)
    gws = {}
    for line in out.splitlines():
        if "default via" in line and "proto static" not in line:
            parts = line.split()
            gw = parts[parts.index("via") + 1]
            dev = parts[parts.index("dev") + 1]
            if dev not in gws:
                gws[dev] = gw
    return gws

def probe_dev(dev):
    for tgt in TARGETS:
        res = subprocess.run(
            ["ping", "-I", dev, "-c", "3", "-i", "0.2", "-W", "1", "-q", tgt],
            capture_output=True, text=True
        )
        m_loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", res.stdout)
        m_rtt = re.search(r"rtt min/avg/max/mdev = [\d.]+/([\d.]+)/", res.stdout)
        loss = float(m_loss.group(1)) if m_loss else 100.0
        rtt = float(m_rtt.group(1)) if m_rtt else 999.0
        if loss < 100.0:
            return loss, rtt
    return 100.0, 999.0

def calc_weight(loss, rtt):
    if loss >= 50.0 or rtt >= 800.0:
        return 0
    score = 1000.0 / max(rtt, 10.0)
    penalty = max(0.1, (100.0 - loss) / 100.0)
    return max(1, min(32, int(round(score * penalty))))

last_state = None
while True:
    gws = get_gateways()
    if gws:
        nexthops = []
        best_dev = None
        best_score = -1
        for dev, gw in sorted(gws.items()):
            loss, rtt = probe_dev(dev)
            w = calc_weight(loss, rtt)
            if w > 0:
                nexthops.append((gw, dev, w, rtt, loss))
                if w > best_score:
                    best_score = w
                    best_dev = dev
        # Если все каналы в просадке, оставляем все с весом 1 чтобы не потерять сеть
        if not nexthops:
            nexthops = [(gw, dev, 1, 999.0, 100.0) for dev, gw in sorted(gws.items())]
            best_dev = nexthops[0][1]

        state_sig = [(gw, dev, w) for gw, dev, w, _, _ in nexthops]
        if state_sig != last_state:
            cmd = ["ip", "route", "replace", "default", "scope", "global", "proto", "static"]
            for gw, dev, w, _, _ in nexthops:
                cmd += ["nexthop", "via", gw, "dev", dev, "weight", str(w)]
            subprocess.run(cmd, stderr=subprocess.DEVNULL)
            last_state = state_sig
            info = " | ".join(f"{dev}: w={w} (rtt={rtt:.1f}ms, loss={loss:.0f}%)" for _, dev, w, rtt, loss in nexthops)
            print(f"[MULTIWAN] Best={best_dev} -> {info}", flush=True)
    time.sleep(3)
