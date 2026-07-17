#!/bin/sh
echo "echo-server: role=$ROLE starting"

mkdir -p /www
cat > /www/index.html <<EOF
{"server":"echo-server","hostname":"$(hostname)","message":"hello from a locally-pushed-and-pulled image"}
EOF

echo "echo-server: serving /www on port 8080 (-v logs each request below)"
exec busybox httpd -f -v -p 8080 -h /www
