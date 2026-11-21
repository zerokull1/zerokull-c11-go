// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://://github.com)
// Licensed under GPL-3.0.

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
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
		Magic:     magic,
		Version:   binary.LittleEndian.Uint32(buf[8:12]),
		PID:       binary.LittleEndian.Uint32(buf[12:16]),
		StartTS:   binary.LittleEndian.Uint64(buf[16:24]),
		Inspected: binary.LittleEndian.Uint64(buf[24:32]),
		Drops:     binary.LittleEndian.Uint64(buf[32:40]),
		Bans:      binary.LittleEndian.Uint64(buf[40:48]),
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
	return fmt.Sprintf(
		"# TYPE zerokull_up gauge\nzerokull_up %d\n"+
			"# TYPE zerokull_uptime_seconds gauge\nzerokull_uptime_seconds %d\n"+
			"# TYPE zerokull_packets_inspected_total counter\nzerokull_packets_inspected_total %d\n"+
			"# TYPE zerokull_packets_dropped_total counter\nzerokull_packets_dropped_total %d\n"+
			"# TYPE zerokull_ips_banned_total counter\nzerokull_ips_banned_total %d\n",
		active, t.UptimeSec, t.Inspected, t.Drops, t.Bans,
	)
}

func main() {
	cmd := "status"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "status":
		t, err := readTelemetry(shmPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "zerokull-ctl: %v\n", err)
			os.Exit(1)
		}
		state := "STOPPED"
		if t.Active {
			state = "ACTIVE"
		}
		fmt.Printf("ZEROKULL CTL | status=%s pid=%d uptime=%ds | inspected=%d drops=%d bans=%d\n",
			state, t.PID, t.UptimeSec, t.Inspected, t.Drops, t.Bans)

	case "serve":
		addr := "127.0.0.1:9109"
		if len(os.Args) > 2 {
			addr = os.Args[2]
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
			t, err := readTelemetry(shmPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = w.Write([]byte(formatPrometheus(t)))
		})
		mux.HandleFunc("/api/v1/stats", func(w http.ResponseWriter, _ *http.Request) {
			t, err := readTelemetry(shmPath)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(t)
		})
		srv := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 2 * time.Second,
			WriteTimeout:      2 * time.Second,
		}
		fmt.Printf("[zerokull-ctl] listening on http://%s (/metrics, /api/v1/stats)\n", addr)
		if err := srv.ListenAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "zerokull-ctl: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "usage: zerokull-ctl [status | serve [addr:port]]\n")
		os.Exit(2)
	}
}
