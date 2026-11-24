#!/usr/bin/env bash
# VEIL 原型一键测试：本地回环握手 + echo、错误密钥静默丢弃、0-RTT 恢复。
# 只输出真实跑出来的结果，不编造。任一测试失败即非零退出。
set -u
cd "$(dirname "$0")"

GO="${GO:-$HOME/workspace/tools/go/bin/go}"
BIN=/tmp/veil-test-bin
WORK=$(mktemp -d)
trap 'kill $SRV_PID 2>/dev/null; rm -rf "$WORK" "$BIN"' EXIT

echo "== build =="
"$GO" build -o "$BIN" . || exit 1
echo "build OK"

echo "== go vet + go test =="
"$GO" vet ./... || exit 1
"$GO" test -v ./... || exit 1

echo "== gen keys (测试用，现生成，用完即弃) =="
"$BIN" genkey --out "$WORK/server.key" > "$WORK/server_pub.txt" || exit 1
"$BIN" genkey --out "$WORK/client.key" > "$WORK/client_pub.txt" || exit 1
SRV_PUB=$(grep -o 'public=[0-9a-f]*' "$WORK/server_pub.txt" | cut -d= -f2)
CLI_PUB=$(grep -o 'public=[0-9a-f]*' "$WORK/client_pub.txt" | cut -d= -f2)
echo "$CLI_PUB" > "$WORK/clients.txt"
echo "server_pub=$SRV_PUB"

PORT=18443
"$BIN" server --listen "127.0.0.1:$PORT" --key "$WORK/server.key" --clients "$WORK/clients.txt" \
  > "$WORK/server.log" 2>&1 &
SRV_PID=$!
sleep 1
kill -0 $SRV_PID || { echo "FAIL: server did not start"; cat "$WORK/server.log"; exit 1; }

PASS=0; FAIL=0
ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

echo "== test 1: 本地回环握手 + echo =="
MSG="VEIL-hello-2026-11-24"
OUT=$("$BIN" client --server "127.0.0.1:$PORT" --server-pub "$SRV_PUB" \
  --client-key "$WORK/client.key" --message "$MSG" --save-ticket "$WORK/ticket.json" 2>&1)
echo "$OUT"
echo "$OUT" | grep -q "HANDSHAKE_OK" && echo "$OUT" | grep -q "ECHO=$MSG" \
  && [ -f "$WORK/ticket.json" ] && ok "test1 handshake+echo (明文原样返回，票据已签发)" \
  || bad "test1 handshake+echo"

echo "== test 2a: 错误服务端公钥 -> 静默丢弃（服务端零字节回包） =="
WRONG_PUB="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
OUT2=$("$BIN" client --server "127.0.0.1:$PORT" --server-pub "$WRONG_PUB" \
  --client-key "$WORK/client.key" --message "$MSG" 2>&1)
RC2=$?
echo "$OUT2"
# 客户端必须失败，且握手阶段收到的服务端字节数为 0（RECV_BYTES=0）
echo "$OUT2" | grep -q "RECV_BYTES=0" && [ "$RC2" -ne 0 ] \
  && ok "test2a wrong server pubkey: client failed, RECV_BYTES=0" \
  || bad "test2a wrong server pubkey (rc=$RC2)"

echo "== test 2b: 未登记的客户端密钥 -> 静默丢弃 =="
"$BIN" genkey --out "$WORK/client2.key" > "$WORK/client2_pub.txt" || exit 1
OUT2B=$("$BIN" client --server "127.0.0.1:$PORT" --server-pub "$SRV_PUB" \
  --client-key "$WORK/client2.key" --message "$MSG" 2>&1)
RC2B=$?
echo "$OUT2B"
echo "$OUT2B" | grep -q "RECV_BYTES=0" && [ "$RC2B" -ne 0 ] \
  && ok "test2b unregistered client key: client failed, RECV_BYTES=0" \
  || bad "test2b unregistered client key (rc=$RC2B)"

echo "== test 2c: 明文乱字节探测 -> 静默丢弃 =="
python3 - "$PORT" <<'PYEOF' > "$WORK/probe.out" 2>&1
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=5)
s.sendall(b"\x00\x01\x02\x03GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" + b"A"*200)
s.settimeout(3)
try:
    data = s.recv(4096)
    print("PROBE_RECV_BYTES=%d" % len(data))
except (socket.timeout, ConnectionResetError):
    # 超时无字节，或服务端直接 RST 关闭：两种情况应用层都收到 0 字节
    print("PROBE_RECV_BYTES=0")
PYEOF
cat "$WORK/probe.out"
grep -q "PROBE_RECV_BYTES=0" "$WORK/probe.out" \
  && ok "test2c garbage probe: server replied 0 bytes" \
  || bad "test2c garbage probe"

echo "== test 3: 0-RTT 票据恢复 =="
OUT3=$("$BIN" client --server "127.0.0.1:$PORT" --server-pub "$SRV_PUB" \
  --client-key "$WORK/client.key" --message "$MSG-0rtt" \
  --resume --ticket "$WORK/ticket.json" --save-ticket "$WORK/ticket2.json" 2>&1)
echo "$OUT3"
echo "$OUT3" | grep -q "HANDSHAKE_OK" && echo "$OUT3" | grep -q "ECHO=$MSG-0rtt" \
  && [ -f "$WORK/ticket2.json" ] && ok "test3 0-RTT resume (早期数据原样返回，新票据已签发)" \
  || bad "test3 0-RTT resume"

echo "== test 3b: 同一票据二次使用 -> 必须被拒绝（单次使用） =="
OUT3B=$("$BIN" client --server "127.0.0.1:$PORT" --server-pub "$SRV_PUB" \
  --client-key "$WORK/client.key" --message "$MSG-0rtt-replay" \
  --resume --ticket "$WORK/ticket.json" 2>&1)
RC3B=$?
echo "$OUT3B"
[ "$RC3B" -ne 0 ] && ok "test3b ticket reuse rejected (rc=$RC3B)" \
  || bad "test3b ticket reuse was NOT rejected"

echo "== server log (节选) =="
grep -E "handshake ok|silent drop" "$WORK/server.log" | head -20

echo "== summary: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ] && echo "ALL TESTS PASSED" || { echo "SOME TESTS FAILED"; exit 1; }
