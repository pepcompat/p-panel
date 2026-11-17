#!/usr/bin/env bash
# Probe every fixture site from INSIDE its node (no host ports are published).
# Exit non-zero if any probe deviates from the expected status code.
# shellcheck source=scripts/lab/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

fail=0
probe() { # node host url expected_code [extra curl args...]
  local node=$1 host=$2 url=$3 want=$4; shift 4
  local got
  got="$(docker exec "$node" curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "Host: ${host}" "$@" "$url" || true)"
  local verdict=PASS; [[ "$got" == "$want" ]] || { verdict=FAIL; fail=1; }
  printf '%-4s %-18s %-28s %-34s want=%s got=%s\n' "$verdict" "$node" "$host" "$url" "$want" "$got"
}

A=ppanel-lab-node-a; B=ppanel-lab-node-b
probe $A example.lab              http://127.0.0.1/          200
probe $A www.example.lab          http://127.0.0.1/          200
probe $A static.example.lab       http://127.0.0.1/          200
probe $A php.example.lab          http://127.0.0.1/          200
probe $A tenant1.php.example.lab  http://127.0.0.1/          200
probe $A api.example.lab          http://127.0.0.1/          200
probe $A api.example.lab          http://127.0.0.1/healthz   200
probe $A secure.example.lab       http://127.0.0.1/          301
probe $A secure.example.lab       https://secure.example.lab/ 200 -k --resolve secure.example.lab:443:127.0.0.1
probe $A dup.example.lab          http://127.0.0.1/          200
probe $A unusual.example.lab      http://127.0.0.1/          200
probe $A legacy-acme.example.lab  http://127.0.0.1/missing   200
probe $A old.example.lab          http://127.0.0.1/          000
probe $A unknown.invalid          http://127.0.0.1/          000
probe $B shop.b.lab               http://127.0.0.1/          200
probe $B api.example.lab          http://127.0.0.1/          200
probe $B localhost                http://127.0.0.1:8088/nginx_status 200

# Content assertions (which duplicate wins, php executed, upstream reached)
echo "-- bodies"
docker exec $A curl -s -H 'Host: dup.example.lab' http://127.0.0.1/
docker exec $A curl -s -H 'Host: php.example.lab' http://127.0.0.1/
docker exec $A curl -s -H 'Host: api.example.lab' http://127.0.0.1/
docker exec $B curl -s -H 'Host: shop.b.lab' http://127.0.0.1/
docker exec $A sh -c 'nginx -t 2>&1 | grep -i conflicting || true'
exit $fail
