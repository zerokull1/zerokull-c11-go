package main

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSIEMFormatAndTelemetry(t *testing.T) {
	buf := make([]byte, shmSize)
	binary.LittleEndian.PutUint64(buf[0:8], shmMagic)
	binary.LittleEndian.PutUint32(buf[8:12], 1)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(os.Getpid()))
	binary.LittleEndian.PutUint64(buf[16:24], 1000)
	binary.LittleEndian.PutUint64(buf[24:32], 500)
	binary.LittleEndian.PutUint64(buf[32:40], 12)
	binary.LittleEndian.PutUint64(buf[40:48], 3)

	tel, err := parseTelemetry(buf, 1042)
	if err != nil || !tel.Active || tel.Bans != 3 {
		t.Fatalf("parse fail: %v %+v", err, tel)
	}
	cef := formatSyslogCEF("node1", time.Unix(1700000000, 0), tel, 4, 1)
	if !strings.Contains(cef, "CEF:0|ZEROKULL|XDP-DataPlane|1.0|102|") || !strings.Contains(cef, "banDelta=1") {
		t.Fatalf("bad CEF: %s", cef)
	}
	prom := formatPrometheus(tel)
	if !strings.Contains(prom, "zerokull_ips_banned_total 3") {
		t.Fatalf("bad prom: %s", prom)
	}
}
