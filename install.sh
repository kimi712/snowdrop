#!/usr/bin/env bash
# sing-box-ours 一键安装脚本（install.sh）
#
# 一条命令，在一台干净的 VPS 上装好我们自己的多协议节点服务。
#   curl -fsSL https://raw.githubusercontent.com/kimi712/snowdrop/main/install.sh | bash -s -- install
# （正式发布前把上面的地址换成真实仓库地址；不要用任何第三方短链。）
#
# 哲学（斯诺登）：
#   这不是“帮你翻墙”，是把隐私还给你。你的节点、你的密钥、你的日志——
#   全在你自己的服务器上，没有任何一家服务商能替你保管、也就不可能出卖。
#   默认零日志是写进配置里的，不是口头承诺；全部代码开源可审计。
#
# 安全底线（对照上游教训）：
#   - 只从 GitHub 官方 Releases 下载 sing-box，并校验 SHA-256；全程不用 --insecure。
#   - 不用任何无源码黑盒二进制；不用外部脚本链（不 curl | bash 第三方脚本）。
#   - 密钥全部本地随机生成，失败就报错退出，绝不 fallback 到共享密钥。
#   - 防火墙只动自己建的 nft 表，绝不清空用户已有规则。
#   - 改配置先校验、再备份、再重载。
#
# 本文件全部原创，与任何上游一键脚本无代码关系。
# 受 sing-box-yg 启发的地方只有一个想法本身：多协议一次装齐。
set -euo pipefail

SB_VERSION="1.14.4"
SB_REPO="SagerNet/sing-box"
SERVICE="sing-box-ours"
BIN="${SB_OURS_BIN:-/usr/local/bin/sing-box}"
ROOT="${SB_OURS_ROOT:-/etc/sing-box-ours}"
GEN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" && pwd)"
GEN_PY="${GEN_DIR}/gen-config.py"
# 管道安装（curl | bash）时 BASH_SOURCE 不是实体文件，GEN_DIR 会退化成当前目录，
# gen-config.py 根本不在那里，安装必失败。此时把管理脚本统一放到 ROOT（/etc/sing-box-ours），
# 之后的管理命令一律走该路径。
if [ ! -f "${BASH_SOURCE[0]:-}" ]; then
  GEN_DIR="$ROOT"
  GEN_PY="$GEN_DIR/gen-config.py"
fi
REPO_RAW="https://raw.githubusercontent.com/kimi712/snowdrop/main"
UNIT="/etc/systemd/system/${SERVICE}.service"
TIMER="/etc/systemd/system/${SERVICE}-update.timer"

# 官方 SHA-256（GitHub Releases API，2026-11-24 核实；升级版本时同步更新此处）。
declare -A SB_SHA256=(
  [amd64]="699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"
  [arm64]="436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26"
  [armv7]="fd164ed45ebc784f657a3e1d0e0ad0f68afdcff864ee57122c2cfed3ddb80a00"
)

TEST_MODE=0
[ -n "${SB_OURS_ROOT:-}" ] && TEST_MODE=1

info()  { echo "[+] $*"; }
warn()  { echo "[!] $*" >&2; }
die()   { echo "[x] $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 环境检测
# ---------------------------------------------------------------------------
detect_os() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      debian|ubuntu) echo "debian" ;;
      rhel|centos|rocky|almalinux|oracle) echo "rhel" ;;
      *) die "不支持的系统：${ID:-未知}。目前支持 Debian / Ubuntu / Oracle Linux / Rocky / Alma。" ;;
    esac
  else
    die "找不到 /etc/os-release，无法识别系统。"
  fi
}

detect_arch() {
  case "$(uname -m)" in
    x86_64)  echo "amd64" ;;
    aarch64) echo "arm64" ;;
    armv7l)  echo "armv7" ;;
    *) die "不支持的架构：$(uname -m)。支持 x86_64 / aarch64 / armv7l。" ;;
  esac
}

need_root() {
  if [ "$TEST_MODE" -eq 1 ]; then
    info "测试模式：跳过 root 检查与系统级操作。"
    return
  fi
  [ "$(id -u)" -eq 0 ] || die "请用 root 运行：先执行 sudo -i 切换到 root，再跑这条命令。"
}

install_deps() {
  [ "$TEST_MODE" -eq 1 ] && return
  local os="$1"
  info "安装依赖：curl tar openssl python3 nftables qrencode（可选）……"
  if [ "$os" = "debian" ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq curl tar openssl python3 nftables iproute2 procps >/dev/null
    apt-get install -y -qq qrencode >/dev/null || warn "qrencode 未装上，二维码功能将不可用。"
  else
    dnf install -y -q curl tar openssl python3 nftables iproute procps-ng >/dev/null \
      || yum install -y -q curl tar openssl python3 nftables iproute procps-ng >/dev/null
    dnf install -y -q qrencode >/dev/null 2>&1 || yum install -y -q qrencode >/dev/null 2>&1 \
      || warn "qrencode 未装上，二维码功能将不可用。"
  fi
}

# ---------------------------------------------------------------------------
# BBR 拥塞控制：TCP 延迟的第一优先级。
# 只在内核支持时开（Oracle ARM 的 Ubuntu 一般都支持）；不支持就跳过并明说，
# 绝不假装开了。Hy2 的 Brutal 是另一条路，由 set-hy2-bandwidth 控制。
# ---------------------------------------------------------------------------
setup_bbr() {
  [ "$TEST_MODE" -eq 1 ] && { info "[测试模式] 跳过 BBR（本机内核无 bbr）。"; return; }
  if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    warn "内核不支持 BBR（可用：$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null)），跳过。TCP 仍可用 cubic。"
    return
  fi
  cat > /etc/sysctl.d/99-sing-box-ours.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl -p /etc/sysctl.d/99-sing-box-ours.conf >/dev/null 2>&1 || true
  info "BBR 已开启：$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
}

# ---------------------------------------------------------------------------
# sing-box 下载与校验
# ---------------------------------------------------------------------------
download_singbox() {
  local arch="$1"
  local want="${SB_SHA256[$arch]}"
  local url="https://github.com/${SB_REPO}/releases/download/v${SB_VERSION}/sing-box-${SB_VERSION}-linux-${arch}.tar.gz"
  local tmp
  tmp="$(mktemp -d)"
  trap "rm -rf '$tmp'" EXIT
  info "下载 sing-box v${SB_VERSION}（${arch}）……"
  curl -fsSL --retry 2 -o "${tmp}/sing-box.tar.gz" "$url" \
    || die "下载失败。请检查网络，或手动下载后放到 ${BIN}。"
  info "校验 SHA-256……"
  local got
  got="$(sha256sum "${tmp}/sing-box.tar.gz" | awk '{print $1}')"
  [ "$got" = "$want" ] || die "SHA-256 不匹配！期望 ${want}，实际 ${got}。拒绝安装。"
  tar --no-same-owner -xzf "${tmp}/sing-box.tar.gz" -C "$tmp"
  mkdir -p "$(dirname "$BIN")"
  install -m 755 "${tmp}/sing-box-${SB_VERSION}-linux-${arch}/sing-box" "$BIN"
  rm -rf "$tmp"
  info "sing-box 已装到 ${BIN}：$("$BIN" version | head -1)"
}

# ---------------------------------------------------------------------------
# 配置生成器自举：管道安装时本地没有仓库文件，从仓库拉一份 gen-config.py；
# 同时把 install.sh 自身落到 GEN_DIR，之后 show/add-user 等管理命令才找得到脚本。
# ---------------------------------------------------------------------------
ensure_gen_py() {
  [ -f "$GEN_PY" ] && return
  info "下载 gen-config.py（本地没有，从仓库拉取）……"
  mkdir -p "$GEN_DIR"
  curl -fsSL --retry 2 -o "$GEN_PY" "$REPO_RAW/gen-config.py" \
    || die "下载 gen-config.py 失败。请检查网络，或先 git clone https://github.com/kimi712/snowdrop.git 再运行 ./install.sh install。"
  if [ ! -f "$GEN_DIR/install.sh" ]; then
    curl -fsSL --retry 2 -o "$GEN_DIR/install.sh" "$REPO_RAW/install.sh" \
      && chmod +x "$GEN_DIR/install.sh" \
      || warn "保存 install.sh 失败，管理命令请用仓库里的 install.sh。"
  fi
}

# ---------------------------------------------------------------------------
# 防火墙：只建自己的 nft 表（inet sbours），绝不碰用户已有规则。
# 端口跳跃靠 DNAT：把跳跃区间转发到 Hy2 / TUIC 的真实端口。
# ---------------------------------------------------------------------------
firewall_apply() {
  [ "$TEST_MODE" -eq 1 ] && { info "[测试模式] 跳过防火墙。"; return; }
  command -v nft >/dev/null 2>&1 || { warn "没有 nft，跳过防火墙配置。请手动放行配置里的端口。"; return; }
  local state="$ROOT/state.json"
  [ -f "$state" ] || die "找不到 $state，请先安装。"
  # 用 python 从 state.json 取端口（不依赖 jq）。
  read -r P_REALITY P_TLS P_HY2 P_TUIC P_TROJAN P_SS P_VMESS P_NAIVE H1 H2 T1 T2 <<< "$(
    python3 - "$state" <<'PYEOF'
import json, sys
st = json.load(open(sys.argv[1]))
p = st["ports"]; h = st["hop"]
print(p["vless_reality"], p["vless_tls"], p["hy2"], p["tuic"], p["trojan"],
      p["ss"], p["vmess"], p["naive"], h["hy2"][0], h["hy2"][1], h["tuic"][0], h["tuic"][1])
PYEOF
  )"
  local nft_file="$ROOT/firewall.nft"
  cat > "$nft_file" <<EOF
# sing-box-ours 专属防火墙规则（只动 inet sbours 这一张表）。
table inet sbours {
  chain input {
    type filter hook input priority filter; policy accept;
    tcp dport { $P_REALITY, $P_TLS, $P_TROJAN, $P_SS, $P_VMESS, $P_NAIVE } accept
    udp dport { $P_HY2, $P_TUIC, $P_SS } accept
  }
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    udp dport $H1-$H2 dnat to :$P_HY2
    udp dport $T1-$T2 dnat to :$P_TUIC
  }
}
EOF
  nft -f "$nft_file" && info "防火墙规则已应用（仅 inet sbours 表）。"
  # 开机自动恢复：systemd 服务在 sing-box 之前应用本文件。
  cat > "/etc/systemd/system/${SERVICE}-firewall.service" <<EOF
[Unit]
Description=sing-box-ours firewall rules
Before=${SERVICE}.service
[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f $nft_file
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable -q "${SERVICE}-firewall.service" 2>/dev/null || true
}

firewall_remove() {
  [ "$TEST_MODE" -eq 1 ] && return
  if command -v nft >/dev/null 2>&1; then
    nft delete table inet sbours 2>/dev/null || true
    info "已删除 nft 表 inet sbours（其他规则未动）。"
  fi
  rm -f "/etc/systemd/system/${SERVICE}-firewall.service"
}

# ---------------------------------------------------------------------------
# geo 规则库：本地 .srs 文件（SagerNet 官方仓库）。
# 用本地文件而不用远程规则集：服务启动时不依赖外网，断网也能起；
# 每周 geo-refresh 重新下载一次即可更新。
# ---------------------------------------------------------------------------
RULESET_DIR="$ROOT/rule-sets"
download_rulesets() {
  mkdir -p "$RULESET_DIR"
  local ok=1
  local base="https://raw.githubusercontent.com"
  download_one() { # $1=URL $2=目标
    local tmp="$2.tmp.$$"
    if curl -fsSL --retry 2 -o "$tmp" "$1" && [ -s "$tmp" ]; then
      mv "$tmp" "$2"
    else
      rm -f "$tmp"
      warn "规则库下载失败：$1（保留旧文件，服务不受影响）"
      ok=0
    fi
  }
  download_one "$base/SagerNet/sing-geosite/rule-set/geosite-cn.srs" "$RULESET_DIR/geosite-cn.srs"
  download_one "$base/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs" "$RULESET_DIR/geosite-category-ads-all.srs"
  download_one "$base/SagerNet/sing-geoip/rule-set/geoip-cn.srs" "$RULESET_DIR/geoip-cn.srs"
  [ "$ok" -eq 1 ] && info "geo 规则库已就绪：$RULESET_DIR"
}

# ---------------------------------------------------------------------------
# systemd 服务与自动更新定时器
# ---------------------------------------------------------------------------
write_unit() {
  [ "$TEST_MODE" -eq 1 ] && { info "[测试模式] 跳过 systemd。"; return; }
  cat > "$UNIT" <<EOF
[Unit]
Description=sing-box-ours node service
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=$BIN run -c $ROOT/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
  cat > "$TIMER" <<EOF
[Unit]
Description=Weekly sing-box-ours update check
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
EOF
  cat > "/etc/systemd/system/${SERVICE}-update.service" <<EOF
[Unit]
Description=sing-box-ours weekly update
[Service]
Type=oneshot
ExecStart=$GEN_DIR/install.sh update --auto
EOF
  cat > "/etc/systemd/system/${SERVICE}-geo-refresh.timer" <<EOF
[Unit]
Description=Weekly sing-box-ours geo rule-set refresh
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
EOF
  cat > "/etc/systemd/system/${SERVICE}-geo-refresh.service" <<EOF
[Unit]
Description=sing-box-ours geo rule-set refresh
[Service]
Type=oneshot
ExecStart=$GEN_DIR/install.sh geo-refresh
EOF
  cat > "/etc/systemd/system/${SERVICE}-expire-check.timer" <<EOF
[Unit]
Description=Daily sing-box-ours expired-user check
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF
  cat > "/etc/systemd/system/${SERVICE}-expire-check.service" <<EOF
[Unit]
Description=sing-box-ours expired-user check
[Service]
Type=oneshot
ExecStart=$GEN_DIR/install.sh expire-check
EOF
  systemctl daemon-reload
  systemctl enable -q "$SERVICE" "${SERVICE}-firewall.service" "${SERVICE}-update.timer" "${SERVICE}-geo-refresh.timer" "${SERVICE}-expire-check.timer" 2>/dev/null || true
  info "systemd 服务、每周更新/规则库刷新、每日到期检查定时器已启用。"
}

reload_service() {
  [ "$TEST_MODE" -eq 1 ] && { info "[测试模式] 跳过服务重载。"; return; }
  "$BIN" check -c "$ROOT/config.json" || die "配置校验未通过，服务未重载。"
  systemctl reload "$SERVICE" 2>/dev/null || systemctl restart "$SERVICE"
  info "服务已重载。"
}

# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------
cmd_install() {
  need_root
  local os arch
  os="$(detect_os)"
  arch="$(detect_arch)"
  install_deps "$os"
  setup_bbr
  [ -x "$BIN" ] || download_singbox "$arch"
  "$BIN" version | head -1
  local domain="" vmess="" naive=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --domain) domain="$2"; shift 2 ;;
      --vmess)  vmess="--vmess"; shift ;;
      --naive)  naive="--naive"; shift ;;
      *) die "未知参数：$1（可用：--domain 域名 --vmess --naive）" ;;
    esac
  done
  download_rulesets
  if [ ! -f "$ROOT/state.json" ]; then
    info "初始化配置（默认用户 default；Reality 端口 443）……"
    # shellcheck disable=SC2086
    SB_OURS_ROOT="$ROOT" python3 "$GEN_PY" --root "$ROOT" --sing-box "$BIN" init \
      --ip "$(curl -fsSL -m 10 https://api.ipify.org || hostname -I | awk '{print $1}')" \
      ${domain:+--domain "$domain"} $vmess $naive
  else
    info "state.json 已存在，跳过初始化；用 regen 重新生成配置。"
    SB_OURS_ROOT="$ROOT" python3 "$GEN_PY" --root "$ROOT" --sing-box "$BIN" regen
  fi
  firewall_apply
  write_unit
  if [ "$TEST_MODE" -eq 0 ]; then
    systemctl restart "$SERVICE"
    sleep 2
    systemctl is-active -q "$SERVICE" || { warn "服务未正常启动，看日志：journalctl -u $SERVICE -n 50"; }
  fi
  echo
  info "安装完成。查看订阅：$GEN_DIR/install.sh show default"
  info "管理命令：$GEN_DIR/install.sh help"
}

cmd_update() {
  need_root
  local auto=0
  [ "${1:-}" = "--auto" ] && auto=1
  local arch latest
  arch="$(detect_arch)"
  latest="$(curl -fsSL -m 20 "https://api.github.com/repos/${SB_REPO}/releases/latest" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['tag_name'].lstrip('v'))")" \
    || die "无法查询最新版本。"
  local current
  current="$("$BIN" version 2>/dev/null | head -1 | awk '{print $3}')"
  if [ "$latest" = "$current" ]; then
    info "已是最新版 v$current。"
    return 0
  fi
  info "发现新版 v$latest（当前 v$current），开始更新……"
  # 注意：自动更新只跟稳定版（latest 接口不返回预发布版）。
  local saved_version="$SB_VERSION"
  SB_VERSION="$latest"
  # 新版 SHA 需从 Releases API 取；取不到就拒绝更新，绝不无校验安装。
  local want
  want="$(curl -fsSL -m 20 "https://api.github.com/repos/${SB_REPO}/releases/tags/v${latest}" \
    | python3 -c "
import json, sys
d = json.load(sys.stdin)
for a in d['assets']:
    if a['name'] == 'sing-box-${latest}-linux-${arch}.tar.gz':
        print(a['digest'].split(':', 1)[1]); break
")"
  [ -n "$want" ] || die "取不到 v$latest 的官方 SHA-256，拒绝更新。"
  SB_SHA256[$arch]="$want"
  cp "$BIN" "${BIN}.bak" 2>/dev/null || true
  download_singbox "$arch"
  SB_VERSION="$saved_version"
  "$BIN" check -c "$ROOT/config.json" || { warn "新版校验配置失败，恢复旧二进制。"; mv "${BIN}.bak" "$BIN"; die "更新中止。"; }
  [ "$TEST_MODE" -eq 0 ] && systemctl restart "$SERVICE"
  info "已更新到 v$latest。"
}

cmd_uninstall() {
  need_root
  [ "$TEST_MODE" -eq 0 ] && systemctl stop "$SERVICE" 2>/dev/null || true
  [ "$TEST_MODE" -eq 0 ] && systemctl disable -q "$SERVICE" "${SERVICE}-update.timer" "${SERVICE}-firewall.service" 2>/dev/null || true
  firewall_remove
  local backup="/root/sing-box-ours-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  if [ -d "$ROOT" ]; then
    tar -czf "$backup" -C "$(dirname "$ROOT")" "$(basename "$ROOT")" 2>/dev/null || true
    info "配置已备份到 $backup（内含全部凭证，请妥善保管或删除）。"
    rm -rf "$ROOT"
  fi
  rm -f "$UNIT" "$TIMER" "/etc/systemd/system/${SERVICE}-update.service" "${BIN}.bak"
  [ "$TEST_MODE" -eq 0 ] && systemctl daemon-reload
  info "已卸载。sing-box 二进制保留在 $BIN（手动删除即可）。"
}

cmd_status() {
  [ "$TEST_MODE" -eq 0 ] && systemctl status "$SERVICE" --no-pager | head -20
  "$BIN" check -c "$ROOT/config.json" && info "配置校验通过。"
  echo "--- 监听端口 ---"
  ss -lntup 2>/dev/null | grep -E "sing-box|$SERVICE" || echo "（未检测到监听端口）"
}

cmd_health() {
  local ok=1
  [ -f "$ROOT/config.json" ] || { warn "缺少 config.json"; ok=0; }
  "$BIN" check -c "$ROOT/config.json" >/dev/null 2>&1 || { warn "配置校验失败"; ok=0; }
  [ "$TEST_MODE" -eq 0 ] && { systemctl is-active -q "$SERVICE" || { warn "服务未运行"; ok=0; }; }
  if [ $ok -eq 1 ]; then info "健康检查通过。"; else die "健康检查发现问题。"; fi
}

cmd_latency() {
  # 一键延迟测试：对每个 TCP 入站端口测 3 次建连耗时；
  # TLS 端口再测 3 次握手耗时（Reality 端口测到的是转发握手耗时）。
  # UDP 端口（Hy2/TUIC）没有有效握手无法直接测，用 ping 作参考。
  # 这测的是“代理本身的开销”，端到端延迟还取决于你到服务器的物理距离。
  local state="$ROOT/state.json"
  [ -f "$state" ] || die "找不到 $state，请先安装。"
  local ip
  ip="$(python3 -c "import json; print(json.load(open('$state'))['server_ip'])")"
  echo "目标：$ip（3 次取中位数；单位毫秒；只测已开启的协议）"
  python3 - "$ROOT/config.json" "$ip" "$state" <<'LATPYEOF'
import json, socket, ssl, statistics, subprocess, sys, time
cfg = json.load(open(sys.argv[1]))
ip = sys.argv[2]
st = json.load(open(sys.argv[3]))
# 只测配置里真实存在的入站：端口、是否 TLS、是否 Reality 转发。
inbounds = [(i["tag"], i["listen_port"], "tls" in i,
             i.get("tls", {}).get("reality", {}).get("enabled", False))
            for i in cfg["inbounds"]]
udp_tags = {"hy2", "tuic"}
def tcp_ms(port, n=3):
    out = []
    for _ in range(n):
        try:
            t0 = time.monotonic()
            s = socket.create_connection((ip, port), timeout=5)
            out.append((time.monotonic() - t0) * 1000)
            s.close()
        except Exception:
            out.append(float("nan"))
    vals = [v for v in out if v == v]
    return statistics.median(vals) if vals else float("nan")
def tls_ms(port, sni, n=3):
    out = []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for _ in range(n):
        try:
            raw = socket.create_connection((ip, port), timeout=5)
            t0 = time.monotonic()
            ss = ctx.wrap_socket(raw, server_hostname=sni)
            out.append((time.monotonic() - t0) * 1000)
            ss.close()
        except Exception:
            out.append(float("nan"))
    vals = [v for v in out if v == v]
    return statistics.median(vals) if vals else float("nan")
print("%-16s %-8s %-12s %-12s" % ("协议", "端口", "TCP建连", "TLS握手"))
for name, port, has_tls, is_reality in sorted(inbounds, key=lambda t: t[1]):
    if name in udp_tags:
        print("%-16s %-8d %-12s %-12s" % (name, port, "UDP", "ping见下"))
        continue
    t = tcp_ms(port)
    def fmt(v):
        return ("%.1f" % v) if v == v else "失败"
    if not has_tls:
        print("%-16s %-8d %-12s %-12s" % (name, port, fmt(t), "非TLS"))
        continue
    h = tls_ms(port, st.get("domain") or "sing-box-ours.local")
    # Reality 端口的 TLS 握手是转发到真站的耗时；失败多为出口网络问题，不是服务端故障。
    hs = ("%.1f" % h) if h == h else ("失败（转发）" if is_reality else "失败")
    print("%-16s %-8d %-12s %-12s" % (name, port, fmt(t), hs))
try:
    r = subprocess.run(["ping", "-c", "3", "-W", "2", ip],
                       capture_output=True, text=True, timeout=15).stdout
    for line in r.splitlines():
        if "avg" in line:
            print("ping %s：%s" % (ip, line.strip().split("=")[1].strip()))
except Exception:
    print("ping 不可用。")
LATPYEOF
}

cmd_traffic() {
  # 流量统计：只计端口总字节数（nft 计数器），不记 IP、不记域名、不记时间。
  # 这是体积统计，不是访问日志；不想要连这个都不要，就别建 nft 规则。
  [ "$TEST_MODE" -eq 1 ] && { info "[测试模式] 无流量计数器。"; return; }
  command -v nft >/dev/null 2>&1 || { warn "没有 nft，无法统计。"; return; }
  echo "--- 各端口累计字节（自本次开机/规则应用起，nft 计数器）---"
  nft list chain inet sbours input 2>/dev/null | grep -E "dport|packets" || echo "（无计数器：规则可能未应用）"
}

cmd_geo_refresh() {
  need_root
  download_rulesets
  SB_OURS_ROOT="$ROOT" python3 "$GEN_PY" --root "$ROOT" --sing-box "$BIN" regen
  reload_service
  info "规则库已刷新。"
}

cmd_expire_check() {
  need_root
  SB_OURS_ROOT="$ROOT" python3 "$GEN_PY" --root "$ROOT" --sing-box "$BIN" expire-check
  reload_service
}

cmd_export() {
  need_root
  [ -d "$ROOT" ] || die "没有可导出的配置（$ROOT 不存在）。"
  local dest="/root/sing-box-ours-export-$(date +%Y%m%d-%H%M%S).tar.gz"
  tar -czf "$dest" -C "$(dirname "$ROOT")" "$(basename "$ROOT")"
  chmod 600 "$dest"
  info "配置已导出到 $dest（内含全部凭证，权限 600，请妥善保管）。"
}

cmd_import() {
  need_root
  local file="${1:-}"
  [ -n "$file" ] && [ -f "$file" ] || die "用法：install.sh import <导出的 tar.gz>"
  local tmp
  tmp="$(mktemp -d)"
  tar --no-same-owner -xzf "$file" -C "$tmp" || die "解包失败：$file"
  local src="$tmp/$(basename "$ROOT")"
  [ -f "$src/state.json" ] || die "包里没有 state.json，不是有效的导出文件。"
  local backup="/root/sing-box-ours-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
  [ -d "$ROOT" ] && tar -czf "$backup" -C "$(dirname "$ROOT")" "$(basename "$ROOT")" 2>/dev/null
  info "当前配置已备份到 $backup。"
  rm -rf "$ROOT"
  cp -a "$src" "$ROOT"
  rm -rf "$tmp"
  SB_OURS_ROOT="$ROOT" python3 "$GEN_PY" --root "$ROOT" --sing-box "$BIN" regen     || { warn "导入的配置校验失败，正在恢复备份。"; rm -rf "$ROOT"; tar -xzf "$backup" -C "$(dirname "$ROOT")"; die "导入中止，已恢复。"; }
  firewall_apply
  reload_service
  info "导入完成。"
}

cmd_gen() {
  # 把管理类子命令透传给 gen-config.py。
  local sub="$1"; shift
  SB_OURS_ROOT="$ROOT" python3 "$GEN_PY" --root "$ROOT" --sing-box "$BIN" "$sub" "$@"
  local rc=$?
  # 增删用户、开关协议、轮换类操作后重载服务；换端口还要重应用防火墙。
  case "$sub" in
    add-user|del-user|warp-on|warp-off|set-domain|set-cert|enable|rotate-sni|rotate-credentials|rotate-user|renew-cert|expire-check|fragment)
      reload_service ;;
    rotate-ports)
      firewall_apply; reload_service ;;
  esac
  # show 带用户名时，如果装了 qrencode，打印 Reality 链接的二维码，手机一扫即用。
  if [ "$sub" = "show" ] && [ $# -ge 1 ] && [ "$rc" -eq 0 ] && command -v qrencode >/dev/null 2>&1; then
    local link_file="$ROOT/subscriptions/$1/links.txt"
    if [ -f "$link_file" ]; then
      local url
      url="$(grep '^VLESS-Reality: ' "$link_file" | sed 's/^VLESS-Reality: //')"
      if [ -n "$url" ]; then
        echo "--- 扫码即用（VLESS Reality）---"
        qrencode -t ANSIUTF8 "$url"
      fi
    fi
  fi
  return $rc
}

cmd_menu() {
  while true; do
    echo
    echo "=== sing-box-ours 管理菜单 ==="
    echo " 1) 查看状态与订阅（show default）"
    echo " 2) 新增用户        3) 删除用户"
    echo " 4) 开启 WARP 分流  5) 关闭 WARP 分流"
    echo " 6) 开启 VMess      7) 健康检查"
    echo " 8) 流量统计（仅端口字节数）"
    echo " 9) 检查更新        0) 退出"
    read -rp "选一项 [0-9]: " n
    case "$n" in
      1) cmd_gen show default ;;
      2) read -rp "新用户名: " u; cmd_gen add-user "$u" ;;
      3) read -rp "要删除的用户名: " u; cmd_gen del-user "$u" ;;
      4) cmd_gen warp-on ;;
      5) cmd_gen warp-off ;;
      6) cmd_gen enable vmess ;;
      7) cmd_health ;;
      8) cmd_traffic ;;
      9) cmd_update ;;
      0) exit 0 ;;
      *) echo "无效选项。" ;;
    esac
  done
}

usage() {
  cat <<EOF
用法：install.sh <命令> [参数]

  install [--domain 域名] [--vmess] [--naive]  一键安装（默认装 Reality+Hy2+TUIC+Trojan+SS）
  update [--auto]     检查并更新 sing-box 到最新稳定版（校验 SHA-256）
  uninstall           卸载（先备份配置到 /root/sing-box-ours-backup-*.tar.gz）
  status              服务状态 + 配置校验 + 监听端口
  health              健康检查（配置、服务）
  traffic             流量统计（仅端口总字节数，不记访问记录）
  show [用户名]       查看状态；带用户名时打印分享链接＋二维码
  add-user <名> [--expires YYYY-MM-DD]  新增用户（独立凭证，可设到期日）
  del-user <名>       删除用户（其链接即刻失效）
  rotate-user <名>    轮换单个用户的全部凭证
  rotate-sni [域名]   轮换 Reality SNI（封锁名单盯上域名时换一张“身份证”）
  rotate-ports        轮换全部非 443 端口与跳跃区间
  rotate-credentials  轮换 Reality 密钥对与 short_id
  renew-cert          重新签发自签证书
  expire-check        删除已过期的用户（每日定时器自动跑）
  fragment <on|off>   开关客户端 TLS fragment
  warp-on / warp-off  开关 WARP 分流
  set-domain <域名>   设置域名（影响 TLS 与 ECH）
  set-cert --cert X --key Y   换用真实证书
  enable <vmess|naive>        开启可选协议
  geo-refresh         刷新 geo 规则库（每周定时器自动跑）
  export / import <文件>      导出 / 导入全部配置（含凭证）
  latency             一键延迟测试（TCP 建连＋TLS 握手耗时）
  set-hy2-bandwidth <上> <下> 设 Hy2 带宽启用 Brutal（0 取消，走 BBR）
  set-mode <low-latency|high-concealment>  双模式：低延迟 / 高隐蔽
  menu                交互菜单
  help                本帮助

环境变量：SB_OURS_ROOT（测试/自定义安装目录）、SB_OURS_BIN（二进制路径）。
EOF
}

main() {
  local cmd="${1:-menu}"; shift || true
  # help 不用 root 也不用生成器；其他命令先查 root 再确保 gen-config.py 在位。
  # 顺序不能反：普通用户先跑 ensure 会在 mkdir /etc/sing-box-ours 上报看不懂的 Permission denied。
  case "$cmd" in
    help|--help|-h) usage ;;
    *) need_root; ensure_gen_py ;;
  esac
  case "$cmd" in
    install)   cmd_install "$@" ;;
    update)    cmd_update "$@" ;;
    uninstall) cmd_uninstall "$@" ;;
    status)    cmd_status "$@" ;;
    health)    cmd_health "$@" ;;
    traffic)   cmd_traffic "$@" ;;
    show|add-user|del-user|warp-on|warp-off|set-domain|set-cert|enable|rotate-sni|rotate-ports|rotate-credentials|rotate-user|renew-cert|expire-check|fragment|set-hy2-bandwidth|set-mode) cmd_gen "$cmd" "$@" ;;
    latency) cmd_latency "$@" ;;
    geo-refresh) cmd_geo_refresh "$@" ;;
    export) cmd_export "$@" ;;
    import) cmd_import "$@" ;;
    menu)      cmd_menu ;;
    help|--help|-h) usage ;;
    *) die "未知命令：$cmd（用 install.sh help 查看）" ;;
  esac
}

main "$@"
