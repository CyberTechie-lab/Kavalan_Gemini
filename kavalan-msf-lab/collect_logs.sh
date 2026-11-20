#!/usr/bin/env bash
# Pull the two logs Kavalan reads out of the Metasploitable container into ./logs/.
# Leave this running in its own terminal tab while you attack. Ctrl+C to stop.
set -u
C=kavalan-msf
mkdir -p logs

if ! docker ps --format '{{.Names}}' | grep -q "^${C}$"; then
  echo "Container '${C}' is not running. Start it first:  docker compose up -d"
  exit 1
fi

echo "Collecting from '${C}' into ./logs/  (auth.log + access.log) — Ctrl+C to stop"

# SSH auth attempts. Path is standard on Metasploitable 2.
docker exec "$C" sh -c 'touch /var/log/auth.log 2>/dev/null; tail -F -n +1 /var/log/auth.log' \
  >> logs/auth.log 2>/dev/null &
P1=$!

# Apache access log. Metasploitable 2 logs to /var/log/apache2/access.log.
docker exec "$C" sh -c 'mkdir -p /var/log/apache2 2>/dev/null; touch /var/log/apache2/access.log 2>/dev/null; tail -F -n +1 /var/log/apache2/access.log' \
  >> logs/access.log 2>/dev/null &
P2=$!

trap 'echo; echo "stopping..."; kill $P1 $P2 2>/dev/null; exit 0' INT TERM
wait
