#!/usr/bin/env bash
# ZEROMANI (zerokull1) | 0x5A45524F4D414E49ULL
set -uo pipefail

sysctl -w net.ipv4.fib_multipath_hash_policy=1 net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2 >/dev/null
sysctl -w net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true

# Собираем все уникальные активные шлюзы (исключая наши ECMP-маршруты proto static)
mapfile -t GWS < <(ip -4 route show default | awk "/default via/ && \$0 !~ /proto static/ {print \$3, \$5}" | awk "!seen[\$2]++")

# Очищаем старые правила fwmark 101..120 и таблицы
for i in $(seq 101 120); do
    ip rule del fwmark "$i" lookup "$i" 2>/dev/null || true
    ip route flush table "$i" 2>/dev/null || true
done
while ip rule show | grep -qE "lookup (10[1-9]|11[0-9]|120)"; do
    PRIO=$(ip rule show | awk "/lookup (10[1-9]|11[0-9]|120)/ {sub(/:/,\"\",\$1); print \$1; exit}")
    [ -n "$PRIO" ] && ip rule del pref "$PRIO" 2>/dev/null || break
done

nft delete table inet multiwan_mesh 2>/dev/null || true
nft add table inet multiwan_mesh
nft add chain inet multiwan_mesh prerouting "{ type filter hook prerouting priority mangle - 5; policy accept; }"
nft add chain inet multiwan_mesh output "{ type route hook output priority mangle - 5; policy accept; }"
nft add chain inet multiwan_mesh postrouting "{ type filter hook postrouting priority mangle; policy accept; }"
nft add chain inet multiwan_mesh srcnat "{ type nat hook postrouting priority srcnat; policy accept; }"

# Восстанавливаем сохраненный ct mark на входящих и исходящих пакетах
nft add rule inet multiwan_mesh prerouting ct mark != 0 meta mark set ct mark
nft add rule inet multiwan_mesh output ct mark != 0 meta mark set ct mark

NEXTHOPS=()
IDX=101
for entry in "${GWS[@]}"; do
    GW=$(echo "$entry" | awk "{print \$1}")
    DEV=$(echo "$entry" | awk "{print \$2}")
    SRC=$(ip -4 -o addr show dev "$DEV" | awk "{split(\$4,a,\"/\"); print a[1]; exit}")
    [ -z "$SRC" ] && continue

    ip link set dev "$DEV" mtu 1380 2>/dev/null || true
    tc qdisc replace dev "$DEV" root fq 2>/dev/null || true

    ip route replace default via "$GW" dev "$DEV" src "$SRC" table "$IDX"
    ip rule add from "$SRC"/32 lookup "$IDX" pref "$IDX"
    ip rule add fwmark "$IDX" lookup "$IDX" pref "$((IDX + 100))"

    # Запоминаем интерфейс в ct mark для входящих и исходящих потоков + ставим TTL=65 и MSS clamp
    nft add rule inet multiwan_mesh prerouting iifname "$DEV" ct state new ct mark set "$IDX"
    nft add rule inet multiwan_mesh postrouting oifname "$DEV" ct mark == 0 ct mark set "$IDX"
    nft add rule inet multiwan_mesh postrouting oifname "$DEV" counter ip ttl set 65
    nft add rule inet multiwan_mesh srcnat oifname "$DEV" counter snat ip to "$SRC"
    nft add rule inet multiwan_mesh postrouting oifname "$DEV" tcp flags syn tcp option maxseg size set rt mtu

    NEXTHOPS+=(nexthop via "$GW" dev "$DEV" weight 1)
    IDX=$((IDX + 1))
done

if [ "${#NEXTHOPS[@]}" -ge 2 ]; then
    ip route replace default scope global proto static "${NEXTHOPS[@]}"
elif [ "${#NEXTHOPS[@]}" -eq 1 ]; then
    ip route replace default scope global proto static "${NEXTHOPS[@]}"
fi
