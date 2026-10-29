#!/bin/sh
set -eu

umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj /CN=localhost \
    -keyout /tmp/haproxy.key \
    -out /tmp/haproxy.crt \
    >/dev/null 2>&1
cat /tmp/haproxy.key /tmp/haproxy.crt > /tmp/haproxy.pem
rm -f /tmp/haproxy.key /tmp/haproxy.crt

exec haproxy -W -db -f /etc/haproxy.cfg
