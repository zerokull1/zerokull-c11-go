// ZEROKULL (zerokull1) | Author Signature: 0x5A45524F4B554C4CULL
// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0.

package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseAndFormat(t *testing.T) {
	buf := make([]byte, shmSize)
	binary.LittleEndian.PutUint64(buf[0:8], shmMagic)
	binary.LittleEndian.PutUint32(buf[8:12], 1)
	binary.LittleEndian.PutUint32(buf[12:16], 0)
	binary.LittleEndian.PutUint64(buf[16:24], 1000)
	binary.LittleEndian.PutUint64(buf[24:32], 50000)
	binary.LittleEndian.PutUint64(buf[32:40], 120)
	binary.LittleEndian.PutUint64(buf[40:48], 5)

	tel, err := parseTelemetry(buf, 1050)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if tel.Inspected != 50000 || tel.Drops != 120 || tel.Bans != 5 {
		t.Fatalf("mismatch: %+v", tel)
	}
	prom := formatPrometheus(tel)
	if !strings.Contains(prom, "zerokull_packets_inspected_total 50000") {
		t.Fatalf("bad prom output: %s", prom)
	}
}
