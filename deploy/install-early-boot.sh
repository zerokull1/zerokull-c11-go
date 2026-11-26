#!/usr/bin/env bash
# ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
set -euo pipefail

mkdir -p /etc/systemd/system/nftables.service.d /etc/systemd/system/zeromani-18caps.service.d /etc/systemd/system/zeromani-core3-guard.service.d

cat << "UNIT" > /etc/systemd/system/nftables.service.d/early-boot.conf
[Unit]
Wants=network-pre.target
Before=network-pre.target NetworkManager.service

[Install]
WantedBy=network-pre.target
UNIT

cat << "UNIT" > /etc/systemd/system/zeromani-18caps.service.d/early-boot.conf
[Unit]
After=
After=local-fs.target systemd-journald.socket
Wants=network-pre.target
Before=network-pre.target NetworkManager.service

[Install]
WantedBy=network-pre.target
UNIT

cat << "UNIT" > /etc/systemd/system/zeromani-core3-guard.service.d/early-boot.conf
[Unit]
After=
After=local-fs.target systemd-journald.socket zeromani-18caps.service
Wants=network-pre.target
Before=network-pre.target NetworkManager.service

[Install]
WantedBy=network-pre.target
UNIT

systemctl daemon-reload
systemctl reenable nftables.service zeromani-18caps.service zeromani-core3-guard.service
