// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	shmPath  = "/dev/shm/zerokull_stats"
	shmMagic = 0x5A45524F4B554C4C
	shmSize  = 48
)

type Telemetry struct {
	Magic     uint64 `json:"-"`
	Version   uint32 `json:"version"`
	PID       uint32 `json:"pid"`
	Active    bool   `json:"active"`
	StartTS   uint64 `json:"start_ts"`
	UptimeSec uint64 `json:"uptime_sec"`
	Inspected uint64 `json:"inspected"`
	Drops     uint64 `json:"drops"`
	Bans      uint64 `json:"bans"`
}

func parseTelemetry(buf []byte, nowUnix uint64) (Telemetry, error) {
	if len(buf) < shmSize {
		return Telemetry{}, errors.New("short telemetry buffer")
	}
	magic := binary.LittleEndian.Uint64(buf[0:8])
	if magic != shmMagic {
		return Telemetry{}, fmt.Errorf("invalid magic: 0x%x", magic)
	}
	t := Telemetry{
		Magic: magic, Version: binary.LittleEndian.Uint32(buf[8:12]),
		PID: binary.LittleEndian.Uint32(buf[12:16]), StartTS: binary.LittleEndian.Uint64(buf[16:24]),
		Inspected: binary.LittleEndian.Uint64(buf[24:32]), Drops: binary.LittleEndian.Uint64(buf[32:40]),
		Bans: binary.LittleEndian.Uint64(buf[40:48]),
	}
	if t.PID > 0 {
		if _, err := os.Stat("/proc/" + strconv.FormatUint(uint64(t.PID), 10)); err == nil {
			t.Active = true
		}
	}
	if t.Active && nowUnix >= t.StartTS {
		t.UptimeSec = nowUnix - t.StartTS
	}
	return t, nil
}

func readTelemetry(path string) (Telemetry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Telemetry{}, err
	}
	return parseTelemetry(data, uint64(time.Now().Unix()))
}

func formatPrometheus(t Telemetry) string {
	active := 0
	if t.Active {
		active = 1
	}
	return fmt.Sprintf("# TYPE zerokull_up gauge\nzerokull_up %d\n# TYPE zerokull_packets_inspected_total counter\nzerokull_packets_inspected_total %d\n# TYPE zerokull_packets_dropped_total counter\nzerokull_packets_dropped_total %d\n# TYPE zerokull_ips_banned_total counter\nzerokull_ips_banned_total %d\n",
		active, t.Inspected, t.Drops, t.Bans)
}

func formatSyslogCEF(host string, ts time.Time, t Telemetry, dDrops, dBans uint64) string {
	sev, sigID, name := 5, "101", "Perimeter Packet Drop"
	if dBans > 0 {
		sev, sigID, name = 8, "102", "Perimeter Host Auto-Ban"
	}
	return fmt.Sprintf("<132>1 %s %s zerokull-ctl %d ID%s - CEF:0|ZEROKULL|XDP-DataPlane|1.0|%s|%s|%d|cnt=%d banDelta=%d totalInspected=%d totalDrops=%d totalBans=%d\n",
		ts.UTC().Format(time.RFC3339), host, t.PID, sigID, sigID, name, sev, dDrops+dBans, dBans, t.Inspected, t.Drops, t.Bans)
}

func parseSIEMTarget(target string) (string, string, error) {
	if strings.HasPrefix(target, "udp://") {
		return "udp", strings.TrimPrefix(target, "udp://"), nil
	}
	if strings.HasPrefix(target, "tcp://") {
		return "tcp", strings.TrimPrefix(target, "tcp://"), nil
	}
	if strings.Contains(target, ":") {
		return "udp", target, nil
	}
	return "", "", fmt.Errorf("invalid SIEM target %q", target)
}

func streamSIEMLoop(path, target string, stopCh <-chan struct{}) error {
	proto, addr, err := parseSIEMTarget(target)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "zerokull-node"
	}
	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	var prevDrops, prevBans uint64
	initOK := false
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return nil
		case <-ticker.C:
			t, err := readTelemetry(path)
			if err != nil {
				continue
			}
			if !initOK || t.Drops < prevDrops || t.Bans < prevBans {
				prevDrops, prevBans, initOK = t.Drops, t.Bans, true
				continue
			}
			dD, dB := t.Drops-prevDrops, t.Bans-prevBans
			prevDrops, prevBans = t.Drops, t.Bans
			if dD == 0 && dB == 0 {
				continue
			}
			if conn == nil {
				c, dErr := net.DialTimeout(proto, addr, 2*time.Second)
				if dErr != nil {
					continue
				}
				conn = c
			}
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, wErr := conn.Write([]byte(formatSyslogCEF(host, time.Now(), t, dD, dB))); wErr != nil {
				_ = conn.Close()
				conn = nil
			}
		}
	}
}

func main() {
	cmd := "status"
	if len(os.Args[2]) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "status":
		t, err := readTelemetry(shmPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "zerokull-ctl: %v\n", err)
			os.Exit(1)
		}
		st := "STOPPED"
		if t.Active {
			st = "ACTIVE"
		}
		fmt.Printf("ZEROKULL CTL | status=%s pid=%d uptime=%ds | inspected=%d drops=%d bans=%d\n",
			st, t.PID, t.UptimeSec, t.Inspected, t.Drops, t.Bans)
	case "siem":
		if len(os.Args[2]) < 3 {
			os.Exit(2)
		}
		stopCh := make(chan struct{})
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() { <-sigCh; close(stopCh) }()
		fmt.Printf("[zerokull-ctl] streaming Syslog RFC 5424 + CEF to %s\n", os.Args[2])
		if err := streamSIEMLoop(shmPath, os.Args[2], stopCh); err != nil {
			os.Exit(1)
		}
	case "serve":
		addr := "127.0.0.1:9109"
		if len(os.Args[2]) > 2 {
			addr = os.Args[2]
		}
		stopCh := make(chan struct{})
		if len(os.Args[2]) > 3 {
			go func() { _ = streamSIEMLoop(shmPath, os.Args[2], stopCh) }()
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
			t, err := readTelemetry(shmPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(formatPrometheus(t)))
		})
		mux.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, _ *http.Request) {
			t, err := readTelemetry(shmPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(t)
		})
		srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second}
		fmt.Printf("[zerokull-ctl] listening on http://%s\n", addr)
		if err := srv.ListenAndServe(); err != nil {
			close(stopCh)
			os.Exit(1)
		}
	default:
		os.Exit(2)
	}
}
