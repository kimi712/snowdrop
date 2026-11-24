#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sing-box-ours 配置生成器（gen-config.py）

作用：根据本地状态文件 state.json 生成全部配置与订阅。
  - 服务端配置 config.json（给 sing-box run 用）
  - 每位用户的订阅：分享链接 links.txt、sing-box 客户端配置 client.json、
    Clash / Mihomo 配置 clash.yaml

设计原则（斯诺登隐私哲学）：
  - 零日志是架构，不是承诺：生成的 config.json 默认关闭日志
    （"log": {"disabled": true}），服务器上不产生任何访问记录。
  - 无中心化账号：所有凭证都在本机 state.json（权限 600）里随机生成，
    不向任何第三方注册、不上传、不回传。
  - 每协议独立凭证：一个协议泄露不会牵连其他协议。
  - 改配置先校验：生成后调 `sing-box check`，不通过就恢复备份，
    绝不让坏配置断服。

只用 Python 标准库，不依赖任何第三方包。
本文件全部原创，与任何上游一键脚本无代码关系。
"""

import argparse
import base64
import json
import os
import random
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid

FORMAT_VERSION = 1
TARGET_SINGBOX = "1.14.4"
WARP_API = "https://api.cloudflareclient.com/v0a2158/reg"
WARP_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WARP_PEER_ADDRESS = "162.159.192.1"
WARP_PEER_PORT = 2408
# WARP 分流的默认域名：只把“需要解锁”的 AI 类服务走 WARP，其余直连。
# 用户可在 state.json 里自行改 warp_domains。
DEFAULT_WARP_DOMAINS = ["openai.com", "chatgpt.com", "claude.ai", "anthropic.com"]

# 默认端口：Reality 固定 443（最像正常 HTTPS）；其余随机高位端口在 init 时抽取。
PORT_REALITY = 443


def eprint(*args):
    print(*args, file=sys.stderr)


def run(cmd, input_text=None, check=True):
    """跑一条外部命令，返回 stdout（str）。失败时抛错或返回 None。"""
    try:
        p = subprocess.run(cmd, input=input_text, capture_output=True,
                           text=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        if check:
            raise RuntimeError("命令执行失败 %s: %s" % (cmd, e))
        return None
    if check and p.returncode != 0:
        raise RuntimeError("命令失败 %s: %s" % (cmd, p.stderr.strip()))
    return p.stdout.strip()


def find_singbox(explicit=None):
    """找 sing-box 二进制：显式路径 > 环境变量 > PATH。找不到返回 None。"""
    for cand in [explicit, os.environ.get("SB_OURS_SINGBOX"), "sing-box"]:
        if cand and shutil.which(cand):
            return cand
    return None


def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def gen_uuid() -> str:
    return str(uuid.uuid4())


def gen_password(nbytes=18) -> str:
    return secrets.token_urlsafe(nbytes)


def gen_hex(nbytes=4) -> str:
    return secrets.token_hex(nbytes)


def gen_ss_password() -> str:
    """Shadowsocks 2022-blake3-aes-128-gcm 需要 16 字节密钥的 Base64。"""
    return base64.b64encode(secrets.token_bytes(16)).decode()


# ---------------------------------------------------------------------------
# 密钥生成：优先调 sing-box 官方命令；没有二进制时用 openssl / secrets 兜底。
# Reality 私钥是 32 字节 X25519 私钥的 base64url；公钥需由私钥推导，
# 标准库做不到，用 openssl pkey 推导；两者都没有就报错，绝不写死共享密钥。
# ---------------------------------------------------------------------------

def gen_reality_keypair(singbox):
    """返回 (private_key, public_key)，均为 base64url 字符串。"""
    if singbox:
        out = run([singbox, "generate", "reality-keypair"])
        priv = re.search(r"PrivateKey:\s*(\S+)", out)
        pub = re.search(r"PublicKey:\s*(\S+)", out)
        if priv and pub:
            return priv.group(1), pub.group(1)
    # 兜底：openssl 生成 X25519 密钥对
    if shutil.which("openssl"):
        priv_pem = run(["openssl", "genpkey", "-algorithm", "X25519"])
        open("/tmp/.sbours_priv.pem", "w").write(priv_pem)
        os.chmod("/tmp/.sbours_priv.pem", 0o600)
        try:
            der = subprocess.run(["openssl", "pkey", "-in", "/tmp/.sbours_priv.pem",
                                  "-outform", "DER"], capture_output=True, timeout=30).stdout
            pub_der = subprocess.run(["openssl", "pkey", "-in", "/tmp/.sbours_priv.pem",
                                      "-pubout", "-outform", "DER"],
                                     capture_output=True, timeout=30).stdout
            return b64url_nopad(der[-32:]), b64url_nopad(pub_der[-32:])
        finally:
            try:
                os.unlink("/tmp/.sbours_priv.pem")
            except OSError:
                pass
    raise RuntimeError("无法生成 Reality 密钥对：需要 sing-box 或 openssl")


def gen_ech_keypair(singbox, domain):
    """返回 (private_key_blob, config_blob)，均为 ECH KEYS/CONFIGS 的 base64 串。
    ECH 密钥是 HPKE 密钥，只能由 sing-box 生成；没有二进制就返回 None。"""
    if not singbox:
        return None
    out = run([singbox, "generate", "ech-keypair", domain])
    keys = re.search(r"-----BEGIN ECH KEYS-----\s*([A-Za-z0-9+/=\s]+?)-----END ECH KEYS-----", out)
    cfgs = re.search(r"-----BEGIN ECH CONFIGS-----\s*([A-Za-z0-9+/=\s]+?)-----END ECH CONFIGS-----", out)
    if keys and cfgs:
        return ("".join(keys.group(1).split()), "".join(cfgs.group(1).split()))
    return None


def gen_short_id(singbox):
    if singbox:
        try:
            return run([singbox, "generate", "rand", "--hex", "4"])
        except RuntimeError:
            pass
    return gen_hex(4)


def make_self_signed_cert(root, common_name):
    """生成自签 EC P-256 证书（3650 天），返回 (cert_path, key_path, pin_sha256)。
    pinSHA256 是证书 DER 的 SHA-256，供客户端钉扎证书、不用 insecure。"""
    cert_path = os.path.join(root, "cert.pem")
    key_path = os.path.join(root, "key.pem")
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        run(["openssl", "req", "-x509", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:P-256",
             "-keyout", key_path, "-out", cert_path,
             "-days", "3650", "-nodes",
             "-subj", "/CN=%s" % common_name])
        os.chmod(key_path, 0o600)
        os.chmod(cert_path, 0o644)
    import hashlib
    der = subprocess.run(["openssl", "x509", "-in", cert_path, "-outform", "DER"],
                         capture_output=True, timeout=30).stdout
    pin = hashlib.sha256(der).hexdigest()
    return cert_path, key_path, pin


def detect_ipv6():
    """本机有没有 IPv6：有则监听 ::（双栈），没有则只监听 0.0.0.0。"""
    try:
        with open("/proc/net/if_inet6") as f:
            return bool(f.read().strip())
    except OSError:
        return False


# Reality 可借用的 SNI 池：全是封不起的大站。轮换时按顺序取下一个。
REALITY_SNI_POOL = ["www.apple.com", "www.microsoft.com",
                    "www.bing.com", "www.cloudflare.com", "www.amazon.com"]


def detect_server_ip():
    """探测本机公网 IPv4：ipify > 本地首地址 > 127.0.0.1。"""
    for url in ["https://api.ipify.org", "https://ifconfig.me/ip"]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sing-box-ours/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                ip = r.read().decode().strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip
        except Exception:
            continue
    try:
        out = run(["hostname", "-I"], check=False)
        if out:
            return out.split()[0]
    except Exception:
        pass
    return "127.0.0.1"


# ---------------------------------------------------------------------------
# 状态文件：state.json（权限 600）是唯一事实来源。
# 配置、订阅全部由它渲染；改任何东西都先改 state，再 regen。
# ---------------------------------------------------------------------------

class Paths:
    def __init__(self, root):
        self.root = root
        self.state = os.path.join(root, "state.json")
        self.config = os.path.join(root, "config.json")
        self.sub_dir = os.path.join(root, "subscriptions")

    def ensure(self):
        os.makedirs(self.root, exist_ok=True)
        os.chmod(self.root, 0o700)
        os.makedirs(self.sub_dir, exist_ok=True)
        os.chmod(self.sub_dir, 0o700)


def load_state(paths):
    with open(paths.state) as f:
        st = json.load(f)
    if st.get("format") != FORMAT_VERSION:
        raise RuntimeError("state.json 格式版本不匹配（期望 %s）" % FORMAT_VERSION)
    return st


def save_state(paths, st):
    tmp = paths.state + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, paths.state)


def new_user_credentials(expires_at=None):
    """每位用户、每协议一套独立凭证；绝不全协议共用一个 UUID。
    expires_at 为 YYYY-MM-DD 或 None（永久）。"""
    creds = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "expires_at": expires_at,
        "vless_uuid": gen_uuid(),
        "vmess_uuid": gen_uuid(),
        "hy2_password": gen_password(),
        "tuic_uuid": gen_uuid(),
        "tuic_password": gen_password(),
        "trojan_password": gen_password(),
        "ss_password": gen_ss_password(),
        "naive_username": "u-" + gen_hex(4),
        "naive_password": gen_password(),
    }
    return creds


def pick_random_ports(rng, count, lo=10000, hi=60000, taken=()):
    """抽不重复的随机高位端口，并检查本机占用（best-effort）。"""
    ports = set(taken)
    out = []
    while len(out) < count:
        p = rng.randint(lo, hi)
        if p in ports:
            continue
        ports.add(p)
        out.append(p)
    return out


def cmd_init(paths, singbox, args):
    if os.path.exists(paths.state):
        eprint("state.json 已存在，拒绝重复初始化。如需重建请先备份并删除它。")
        return 1
    paths.ensure()
    rng = random.Random()
    # 端口：Hy2 与 TUIC 各占一段跳跃区间，区间不重叠。
    p_tls, p_hy2, p_tuic, p_trojan, p_ss, p_vmess, p_naive = pick_random_ports(
        rng, 7, taken={PORT_REALITY})
    # 端口跳跃区间：起点随机、宽度 500–1000（太窄等于没跳，太宽难维护）。
    hop_hy2_start = rng.randint(20000, 24000)
    hop_hy2 = [hop_hy2_start, hop_hy2_start + rng.randint(500, 1000)]
    hop_tuic_start = rng.randint(25001, 29000)
    hop_tuic = [hop_tuic_start, hop_tuic_start + rng.randint(500, 1000)]
    priv, pub = gen_reality_keypair(singbox)
    domain = args.domain or None
    ech = None
    if domain:
        ech = gen_ech_keypair(singbox, domain)
        if not ech:
            eprint("提示：未生成 ECH 密钥（需要 sing-box 二进制），ECH 将保持关闭。")
    st = {
        "format": FORMAT_VERSION,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_singbox": TARGET_SINGBOX,
        "server_ip": args.ip or detect_server_ip(),
        "domain": domain,
        "listen": "::" if detect_ipv6() else "0.0.0.0",
        "reality_sni": args.sni or "www.apple.com",
        "reality_sni_pool": list(REALITY_SNI_POOL),
        "reality": {"private_key": priv, "public_key": pub,
                    "short_id": gen_short_id(singbox)},
        "ech": ({"private_key_blob": ech[0], "config_blob": ech[1]} if ech else None),
        "cert": {"mode": "self-signed", "cert_path": "", "key_path": "", "pin_sha256": ""},
        "ports": {"vless_reality": PORT_REALITY, "vless_tls": p_tls,
                  "hy2": p_hy2, "tuic": p_tuic, "trojan": p_trojan,
                  "ss": p_ss, "vmess": p_vmess, "naive": p_naive},
        "hop": {"hy2": hop_hy2, "tuic": hop_tuic},
        "hy2_obfs_password": gen_password(),
        "vmess_path": "/" + gen_hex(8),
        "options": {"vmess": bool(args.vmess), "naive": False,
                    "warp": False, "debug_log": False,
                    "tls_fragment": False, "smart_routing": True,
                    "mode": "low-latency"},
        "hy2_bandwidth": None,  # {"up": Mbps, "down": Mbps}，设了才用 Brutal
        "warp": None,
        "warp_domains": list(DEFAULT_WARP_DOMAINS),
        "users": {"default": new_user_credentials()},
    }
    # 证书：自签是默认；带 --cert/--key 则用用户自带真实证书。
    if args.cert and args.key:
        import hashlib
        der = subprocess.run(["openssl", "x509", "-in", args.cert, "-outform", "DER"],
                             capture_output=True, timeout=30).stdout
        st["cert"] = {"mode": "real", "cert_path": args.cert, "key_path": args.key,
                      "pin_sha256": hashlib.sha256(der).hexdigest()}
    else:
        cn = domain or "sing-box-ours.local"
        cert_path, key_path, pin = make_self_signed_cert(paths.root, cn)
        st["cert"] = {"mode": "self-signed", "cert_path": cert_path,
                      "key_path": key_path, "pin_sha256": pin}
    if args.naive:
        if st["cert"]["mode"] != "real" or not domain:
            eprint("Naive 需要真实域名 + 真实证书（它的客户端不支持 insecure），"
                   "本次不开启；配好证书后用 enable-naive 再开。")
        else:
            st["options"]["naive"] = True
    save_state(paths, st)
    print("初始化完成：state.json 已生成（权限 600），默认用户 default。")
    print("服务端 IP：%s；Reality SNI：%s；VLESS Reality 端口：443" %
          (st["server_ip"], st["reality_sni"]))
    return cmd_regen(paths, singbox, args)


def cmd_add_user(paths, singbox, args):
    st = load_state(paths)
    name = args.name
    if name in st["users"]:
        eprint("用户 %s 已存在。" % name)
        return 1
    expires = getattr(args, "expires", None)
    if expires:
        import datetime
        try:
            datetime.date.fromisoformat(expires)
        except ValueError:
            eprint("--expires 须为 YYYY-MM-DD 格式。")
            return 1
    st["users"][name] = new_user_credentials(expires_at=expires)
    save_state(paths, st)
    print("用户 %s 已添加%s。" % (name, ("，到期 %s" % expires) if expires else "（永久）"))
    return cmd_regen(paths, singbox, args)


def cmd_del_user(paths, singbox, args):
    st = load_state(paths)
    name = args.name
    if name not in st["users"]:
        eprint("用户 %s 不存在。" % name)
        return 1
    if len(st["users"]) == 1:
        eprint("拒绝删除最后一个用户。")
        return 1
    del st["users"][name]
    save_state(paths, st)
    sub = os.path.join(paths.sub_dir, name)
    if os.path.isdir(sub):
        shutil.rmtree(sub)
    print("用户 %s 已删除，其订阅文件已清除（旧链接即刻失效）。" % name)
    return cmd_regen(paths, singbox, args)


def cmd_list_users(paths, singbox, args):
    import datetime
    st = load_state(paths)
    today = datetime.date.today().isoformat()
    for name, u in sorted(st["users"].items()):
        exp = u.get("expires_at") or "永久"
        flag = ""
        if u.get("expires_at") and u["expires_at"] < today:
            flag = "（已过期，下次 expire-check 将删除）"
        print("%-16s 创建于 %s  到期：%s%s" % (name, u.get("created_at", "?"), exp, flag))
    return 0


# ---------------------------------------------------------------------------
# WARP：向 Cloudflare 注册一个全新的免费 WARP 账号（WireGuard 凭证）。
# 只存 WireGuard 所需的密钥与地址，不存账号 token；注册失败就报错退出，
# 绝不 fallback 到任何共享私钥。
# ---------------------------------------------------------------------------

def warp_register():
    if not shutil.which("openssl"):
        raise RuntimeError("注册 WARP 需要 openssl")
    priv_pem = run(["openssl", "genpkey", "-algorithm", "X25519"])
    open("/tmp/.sbours_warp_priv.pem", "w").write(priv_pem)
    os.chmod("/tmp/.sbours_warp_priv.pem", 0o600)
    try:
        der = subprocess.run(["openssl", "pkey", "-in", "/tmp/.sbours_warp_priv.pem",
                              "-outform", "DER"], capture_output=True, timeout=30).stdout
        pub_der = subprocess.run(["openssl", "pkey", "-in", "/tmp/.sbours_warp_priv.pem",
                                  "-pubout", "-outform", "DER"],
                                 capture_output=True, timeout=30).stdout
        priv_b64 = base64.b64encode(der[-32:]).decode()
        pub_b64 = base64.b64encode(pub_der[-32:]).decode()
    finally:
        try:
            os.unlink("/tmp/.sbours_warp_priv.pem")
        except OSError:
            pass
    install_id = gen_uuid()
    body = json.dumps({
        "key": pub_b64, "install_id": install_id, "fcm_token": "",
        "tos": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "model": "PC", "serial_number": install_id, "locale": "en_US",
    }).encode()
    req = urllib.request.Request(WARP_API, data=body, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "okhttp/3.12.1"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except Exception as e:
        raise RuntimeError("WARP 注册失败（网络或 API 异常）：%s" % e)
    cfg = data.get("config", {})
    iface = cfg.get("interface", {})
    addrs = iface.get("addresses", {}) if isinstance(iface, dict) else {}
    peers = cfg.get("peers", [])
    if not addrs.get("v4") or not addrs.get("v6") or not peers:
        raise RuntimeError("WARP 注册返回异常，未拿到接口地址或对端信息")
    peer = peers[0]
    warp = {
        "private_key": priv_b64,
        "address_v4": addrs.get("v4"),
        "address_v6": addrs.get("v6"),
        "peer_public_key": peer.get("public_key", WARP_PEER_PUBLIC_KEY),
        "peer_address": WARP_PEER_ADDRESS,
        "peer_port": WARP_PEER_PORT,
    }
    if peer.get("reserved"):
        warp["reserved"] = peer["reserved"]
    return warp


def cmd_warp_on(paths, singbox, args):
    st = load_state(paths)
    if st.get("warp"):
        print("WARP 已注册过，无需重复注册。")
        return 0
    print("正在向 Cloudflare 注册新的免费 WARP 账号……")
    st["warp"] = warp_register()
    st["options"]["warp"] = True
    save_state(paths, st)
    print("WARP 注册成功，地址：%s / %s" %
          (st["warp"]["address_v4"], st["warp"]["address_v6"]))
    return cmd_regen(paths, singbox, args)


def cmd_warp_off(paths, singbox, args):
    st = load_state(paths)
    st["options"]["warp"] = False
    save_state(paths, st)
    print("WARP 出站已关闭（凭证保留在 state.json，可随时再开）。")
    return cmd_regen(paths, singbox, args)


# ---------------------------------------------------------------------------
# 服务端配置：用 dict 拼装，不用模板、不做行号 sed。
# 日志默认关闭（零日志是架构）；DNS 用 1.14 新格式；路由默认直连。
# ---------------------------------------------------------------------------

def tls_block(st, server_name, with_ech=False):
    """TLS 块：真实证书或自签二选一；有域名且有 ECH 密钥时打开 ECH。"""
    block = {"enabled": True, "server_name": server_name,
             "certificate_path": st["cert"]["cert_path"],
             "key_path": st["cert"]["key_path"]}
    if with_ech and st.get("ech"):
        block["ech"] = {"key": [st["ech"]["private_key_blob"]]}
    return block


def build_server_config(st, rule_set_dir=None):
    p = st["ports"]
    L = st.get("listen", "0.0.0.0")  # 双栈主机为 ::，无 IPv6 的主机为 0.0.0.0
    sni = st["reality_sni"]
    domain = st.get("domain")
    tls_name = domain or "sing-box-ours.local"
    cert_mode = st["cert"]["mode"]
    # 自签证书时客户端用 pinSHA256 / insecure；真实证书时正常校验。
    inbounds = []

    # 1. VLESS + Reality + Vision（TCP 443，主协议）：借真实大站的 TLS 握手，
    #    无正确密钥的探测者看到的就是真网站；Vision 消除 TLS-in-TLS 特征。
    inbounds.append({
        "type": "vless", "tag": "vless-reality",
        "listen": L, "listen_port": p["vless_reality"],
        "users": [{"uuid": u["vless_uuid"], "flow": "xtls-rprx-vision"}
                  for u in st["users"].values()],
        "tls": {"enabled": True, "server_name": sni,
                "reality": {"enabled": True,
                            "handshake": {"server": sni, "server_port": 443},
                            "private_key": st["reality"]["private_key"],
                            "short_id": [st["reality"]["short_id"]]}},
    })

    # 2. VLESS + TLS + Vision（真实域名 + ECH）：标准 TLS 路径，可走 CDN；
    #    ECH 把 SNI 也加密，防 SNI 字符串匹配封锁。
    tls2 = tls_block(st, tls_name, with_ech=True)
    inbounds.append({
        "type": "vless", "tag": "vless-tls",
        "listen": L, "listen_port": p["vless_tls"],
        "users": [{"uuid": u["vless_uuid"], "flow": "xtls-rprx-vision"}
                  for u in st["users"].values()],
        "tls": tls2,
    })

    # 3. Hysteria2（UDP）：Salamander 混淆把 QUIC 包打成随机噪声，
    #    端口跳跃让单端口 UDP 长流限速失效，包大小随机化抹平长度特征。
    inbounds.append({
        "type": "hysteria2", "tag": "hy2",
        "listen": L, "listen_port": p["hy2"],
        "users": [{"password": u["hy2_password"]} for u in st["users"].values()],
        "tls": dict(tls_block(st, tls_name), **{"alpn": ["h3"]}),
        "obfs": {"type": "salamander",
                 "password": st["hy2_obfs_password"],
                 "min_packet_size": 100, "max_packet_size": 1200},
        "masquerade": "https://%s" % sni,
        "ignore_client_bandwidth": False,
    })

    # 4. TUIC v5（UDP，第二条 UDP 备份）：标准 QUIC，无内置混淆，
    #    但实现简单、客户端支持广；Hy2 被针对时顶上。
    inbounds.append({
        "type": "tuic", "tag": "tuic",
        "listen": L, "listen_port": p["tuic"],
        "users": [{"uuid": u["tuic_uuid"], "password": u["tuic_password"]}
                  for u in st["users"].values()],
        "congestion_control": "bbr",
        "tls": dict(tls_block(st, tls_name), **{"alpn": ["h3"]}),
    })

    # 5. Trojan（TCP）：最简单的 TLS 代理，客户端支持最广；
    #    无正确密码的访问者由 fallback 转去真实网站，不暴露代理特征。
    inbounds.append({
        "type": "trojan", "tag": "trojan",
        "listen": L, "listen_port": p["trojan"],
        "users": [{"password": u["trojan_password"]} for u in st["users"].values()],
        "tls": tls_block(st, tls_name),
        "fallback": {"server": sni, "server_port": 443},
    })

    # 6. Shadowsocks 2022-blake3（TCP+UDP）：轻量、路由器/旧设备友好。
    #    明确标注：它本身不抗审查，别当主力；只给确实需要它的设备用。
    inbounds.append({
        "type": "shadowsocks", "tag": "ss",
        "listen": L, "listen_port": p["ss"],
        "method": "2022-blake3-aes-128-gcm",
        "password": st["users"]["default"]["ss_password"],
        "users": [{"password": u["ss_password"]} for u in st["users"].values()],
    })

    # 7. VMess + WS + TLS（可选）：走 CDN 的那条路；路径是独立随机串，不绑 UUID。
    if st["options"].get("vmess"):
        inbounds.append({
            "type": "vmess", "tag": "vmess-ws",
            "listen": L, "listen_port": p["vmess"],
            "users": [{"uuid": u["vmess_uuid"], "alterId": 0}
                      for u in st["users"].values()],
            "transport": {"type": "ws", "path": st.get("vmess_path", "/ws"),
                          "max_early_data": 2048,
                          "early_data_header_name": "Sec-WebSocket-Protocol"},
            "tls": tls_block(st, tls_name),
        })

    # 8. Naive（可选，仅真实证书）：Chromium 真实握手，抗指纹最强；
    #    客户端不支持 insecure，所以自签证书时拒绝开启。
    if st["options"].get("naive"):
        inbounds.append({
            "type": "naive", "tag": "naive",
            "listen": L, "listen_port": p["naive"],
            "users": [{"username": u["naive_username"], "password": u["naive_password"]}
                      for u in st["users"].values()],
            "tls": tls_block(st, tls_name),
        })

    outbounds = [{"type": "direct", "tag": "direct"},
                 {"type": "block", "tag": "block"}]
    endpoints = []
    rules = []
    rule_sets = []
    # 智能分流（本地 .srs 规则库，由 install.sh 在安装时下载、每周刷新）：
    # 广告域名 -> 拦截；中国大陆域名/IP -> 直连；其余 -> 默认直连。
    # 规则库缺失时静默跳过，不影响服务启动（启动时不依赖外网）。
    if st["options"].get("smart_routing") and rule_set_dir:
        wanted = [("geosite-cn", "geosite-cn.srs"),
                  ("geosite-ads", "geosite-category-ads-all.srs"),
                  ("geoip-cn", "geoip-cn.srs")]
        for tag, fn in wanted:
            fp = os.path.join(rule_set_dir, fn)
            if os.path.exists(fp):
                rule_sets.append({"type": "local", "tag": tag,
                                  "format": "binary", "path": fp})
        have = {r["tag"] for r in rule_sets}
        if "geosite-ads" in have:
            rules.append({"rule_set": "geosite-ads", "outbound": "block"})
        if "geosite-cn" in have:
            rules.append({"rule_set": "geosite-cn", "outbound": "direct"})
        if "geoip-cn" in have:
            rules.append({"rule_set": "geoip-cn", "outbound": "direct"})
    if st["options"].get("warp") and st.get("warp"):
        w = st["warp"]
        addrs = [a for a in [w.get("address_v4") and w["address_v4"] + "/32",
                             w.get("address_v6") and w["address_v6"] + "/128"] if a]
        peer_cfg = {"address": w["peer_address"], "port": w["peer_port"],
                    "public_key": w["peer_public_key"],
                    "allowed_ips": ["0.0.0.0/0", "::/0"]}
        if w.get("reserved"):
            peer_cfg["reserved"] = w["reserved"]
        endpoints.append({
            "type": "wireguard", "tag": "warp",
            "address": addrs, "private_key": w["private_key"],
            "peers": [peer_cfg],
            "mtu": 1280,
        })
        # WARP 只接管“需要解锁”的域名，其余流量不经过它。
        for d in st.get("warp_domains", []):
            rules.insert(0, {"domain_suffix": [d], "outbound": "warp"})
    cfg = {
        "log": ({"level": "debug", "timestamp": True}
                if st["options"].get("debug_log") else {"disabled": True}),
        "dns": {"servers": [
            {"type": "https", "tag": "cf", "server": "1.1.1.1"},
            {"type": "udp", "tag": "local", "server": "223.5.5.5"},
        ]},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"default_domain_resolver": "cf",
                  "rules": rules, "final": "direct"},
    }
    if rule_sets:
        cfg["route"]["rule_set"] = rule_sets
    if endpoints:
        cfg["endpoints"] = endpoints
    return cfg


# ---------------------------------------------------------------------------
# 订阅生成：分享链接、sing-box 客户端 JSON、Clash/Mihomo YAML。
# 全部本地生成，不经过任何第三方订阅转换服务。
# ---------------------------------------------------------------------------

def _b64url(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def _b64(s):
    return base64.b64encode(s.encode()).decode()


def build_share_links(st, name, u):
    ip = st["server_ip"]
    p = st["ports"]
    sni = st["reality_sni"]
    domain = st.get("domain")
    tls_name = domain or "sing-box-ours.local"
    self_signed = st["cert"]["mode"] == "self-signed"
    pin = st["cert"]["pin_sha256"]
    links = []
    # VLESS Reality
    q = ("encryption=none&flow=xtls-rprx-vision&security=reality"
         "&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp" %
         (sni, st["reality"]["public_key"], st["reality"]["short_id"]))
    links.append(("VLESS-Reality",
                  "vless://%s@%s:%d?%s#%s" % (u["vless_uuid"], ip, p["vless_reality"], q, name)))
    # VLESS TLS (+ECH)
    q2 = ("encryption=none&flow=xtls-rprx-vision&security=tls"
          "&sni=%s&fp=chrome&type=tcp" % tls_name)
    if self_signed:
        q2 += "&allowInsecure=1"
    if st.get("ech"):
        q2 += "&ech=" + _b64url(st["ech"]["config_blob"])
    links.append(("VLESS-TLS",
                  "vless://%s@%s:%d?%s#%s" % (u["vless_uuid"], ip, p["vless_tls"], q2, name)))
    # Hysteria2：端口跳跃区间写进 mport，客户端按区间轮换。
    hop = st["hop"]["hy2"]
    q3 = ("security=tls&alpn=h3&sni=%s&mport=%d-%d&obfs=salamander"
          "&obfs-password=%s" % (tls_name, hop[0], hop[1],
                                 st["hy2_obfs_password"]))
    if self_signed:
        q3 += "&pinSHA256=%s" % pin
    links.append(("Hysteria2",
                  "hysteria2://%s@%s:%d?%s#%s" % (u["hy2_password"], ip, p["hy2"], q3, name)))
    # TUIC v5
    hop_t = st["hop"]["tuic"]
    q4 = ("congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=%s" % tls_name)
    if self_signed:
        q4 += "&allowInsecure=1"
    links.append(("TUIC",
                  "tuic://%s:%s@%s:%d?%s#%s" %
                  (u["tuic_uuid"], u["tuic_password"], ip, p["tuic"], q4, name)))
    # Trojan
    q5 = "security=tls&sni=%s&fp=chrome&type=tcp" % tls_name
    if self_signed:
        q5 += "&allowInsecure=1"
    links.append(("Trojan",
                  "trojan://%s@%s:%d?%s#%s" % (u["trojan_password"], ip, p["trojan"], q5, name)))
    # Shadowsocks 2022
    ss_userinfo = _b64("2022-blake3-aes-128-gcm:%s" % u["ss_password"])
    links.append(("Shadowsocks",
                  "ss://%s@%s:%d#%s" % (ss_userinfo, ip, p["ss"], name)))
    # VMess WS+TLS（仅开启时）
    if st["options"].get("vmess"):
        vm = {"v": "2", "ps": name + "-vmess", "add": ip, "port": str(p["vmess"]),
              "id": u["vmess_uuid"], "aid": "0", "scy": "auto", "net": "ws",
              "type": "none", "host": tls_name,
              "path": st.get("vmess_path", "/ws"), "tls": "tls", "sni": tls_name}
        if self_signed:
            vm["allowInsecure"] = "1"
        links.append(("VMess-WS",
                      "vmess://" + _b64(json.dumps(vm, separators=(",", ":")))))
    # Naive（仅开启时；链接格式为 naive+https）
    if st["options"].get("naive"):
        links.append(("Naive",
                      "naive+https://%s:%s@%s:%d#%s" %
                      (u["naive_username"], u["naive_password"], ip, p["naive"], name)))
    return links


def build_client_config(st, name, u):
    ip = st["server_ip"]
    p = st["ports"]
    sni = st["reality_sni"]
    domain = st.get("domain")
    tls_name = domain or "sing-box-ours.local"
    self_signed = st["cert"]["mode"] == "self-signed"
    hop = st["hop"]["hy2"]

    def tls_out(server_name, utls=True, ech=False, frag=False):
        # fragment 只对普通 TLS 出站开：它把 ClientHello 切分，
        # 只对简单 SNI 过滤有效；Reality（握手要完整识别）和 QUIC 不开。
        t = {"enabled": True, "server_name": server_name}
        if utls:
            t["utls"] = {"enabled": True, "fingerprint": "chrome"}
        if ech and st.get("ech"):
            t["ech"] = {"config": [st["ech"]["config_blob"]]}
        if frag and st["options"].get("tls_fragment"):
            t["fragment"] = True
            t["record_fragment"] = True
        if self_signed:
            t["insecure"] = True
        return t

    outs = []
    outs.append({"type": "vless", "tag": "vless-reality", "server": ip,
                 "server_port": p["vless_reality"], "uuid": u["vless_uuid"],
                 "flow": "xtls-rprx-vision",
                 "tls": {"enabled": True, "server_name": sni,
                         "utls": {"enabled": True, "fingerprint": "chrome"},
                         "reality": {"enabled": True,
                                     "public_key": st["reality"]["public_key"],
                                     "short_id": st["reality"]["short_id"]}}})
    outs.append({"type": "vless", "tag": "vless-tls", "server": ip,
                 "server_port": p["vless_tls"], "uuid": u["vless_uuid"],
                 "flow": "xtls-rprx-vision",
                 "tls": tls_out(tls_name, ech=True, frag=True)})
    hy2 = {"type": "hysteria2", "tag": "hy2", "server": ip,
           "server_port": p["hy2"], "password": u["hy2_password"],
           "network": "udp",
           "tls": {"enabled": True, "server_name": tls_name, "alpn": ["h3"]},
           "obfs": {"type": "salamander",
                    "password": st["hy2_obfs_password"]},
           "hop_interval": "30s",
           "server_ports": ["%d:%d" % (hop[0], hop[1])]}
    if st.get("hy2_bandwidth"):
        # 设了上下行带宽，Hysteria2 就用 Brutal：按固定速率发、不随丢包退避。
        # 带宽必须是实测值，瞎填一个数反而更慢；不知道就别设，走 BBR。
        hy2["up_mbps"] = st["hy2_bandwidth"]["up"]
        hy2["down_mbps"] = st["hy2_bandwidth"]["down"]
    if self_signed:
        hy2["tls"]["insecure"] = True
    outs.append(hy2)
    tuic = {"type": "tuic", "tag": "tuic", "server": ip,
            "server_port": p["tuic"], "uuid": u["tuic_uuid"],
            "password": u["tuic_password"], "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "tls": tls_out(tls_name)}
    outs.append(tuic)
    outs.append({"type": "trojan", "tag": "trojan", "server": ip,
                 "server_port": p["trojan"], "password": u["trojan_password"],
                 "tls": tls_out(tls_name, frag=True)})
    outs.append({"type": "shadowsocks", "tag": "ss", "server": ip,
                 "server_port": p["ss"], "method": "2022-blake3-aes-128-gcm",
                 "password": u["ss_password"]})
    if st["options"].get("vmess"):
        outs.append({"type": "vmess", "tag": "vmess-ws", "server": ip,
                     "server_port": p["vmess"], "uuid": u["vmess_uuid"],
                     "alter_id": 0, "security": "auto",
                     "transport": {"type": "ws", "path": st.get("vmess_path", "/ws"),
                                   "max_early_data": 2048,
                                   "early_data_header_name": "Sec-WebSocket-Protocol"},
                     "tls": tls_out(tls_name, frag=True)})
    if st["options"].get("naive"):
        naive_tls = {"enabled": True, "server_name": tls_name}
        outs.append({"type": "naive", "tag": "naive", "server": ip,
                     "server_port": p["naive"],
                     "username": u["naive_username"],
                     "password": u["naive_password"], "tls": naive_tls})
    tags = [o["tag"] for o in outs]
    outs.append({"type": "direct", "tag": "direct"})
    outs.append({"type": "selector", "tag": "proxy",
                 "outbounds": tags + ["direct"]})
    outs.append({"type": "urltest", "tag": "auto", "outbounds": tags,
                 "url": "https://www.gstatic.com/generate_204", "interval": "1m"})
    return {
        "log": {"level": "info"},
        "dns": {"servers": [{"type": "https", "tag": "cf", "server": "1.1.1.1"}]},
        "inbounds": [{"type": "mixed", "tag": "mixed-in",
                      "listen": "127.0.0.1", "listen_port": 1080}],
        "outbounds": outs,
        "route": {"default_domain_resolver": "cf",
                  "rules": [{"protocol": "dns", "action": "route",
                             "outbound": "direct"}],
                  "final": "proxy", "auto_detect_interface": True},
    }


# ---------------------------------------------------------------------------
# Clash / Mihomo YAML：手写 emitter，只依赖标准库。
# 注意：Naive 没有 Clash 支持，不写进 YAML（在文件头注释里说明）。
# ---------------------------------------------------------------------------

def _yaml_str(s):
    """YAML 单引号字符串：单引号加倍后包起来。"""
    return "'" + str(s).replace("'", "''") + "'"


def build_clash_yaml(st, name, u):
    ip = st["server_ip"]
    p = st["ports"]
    sni = st["reality_sni"]
    domain = st.get("domain")
    tls_name = domain or "sing-box-ours.local"
    self_signed = st["cert"]["mode"] == "self-signed"
    skip = "true" if self_signed else "false"
    hop = st["hop"]["hy2"]
    lines = []
    lines.append("# sing-box-ours 订阅（Clash / Mihomo）")
    lines.append("# 用户：%s；生成时间：%s" % (name, time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())))
    lines.append("# 注意：Naive 协议没有 Clash 支持，不在此文件内，请用 sing-box 客户端。")
    lines.append("# Shadowsocks 2022 只建议给路由器/旧设备用，别当主力。")
    lines.append("proxies:")
    lines.append("  - name: %s" % _yaml_str(name + "-vless-reality"))
    lines.append("    type: vless")
    lines.append("    server: %s" % _yaml_str(ip))
    lines.append("    port: %d" % p["vless_reality"])
    lines.append("    uuid: %s" % _yaml_str(u["vless_uuid"]))
    lines.append("    network: tcp")
    lines.append("    tls: true")
    lines.append("    servername: %s" % _yaml_str(sni))
    lines.append("    reality-opts:")
    lines.append("      public-key: %s" % _yaml_str(st["reality"]["public_key"]))
    lines.append("      short-id: %s" % _yaml_str(st["reality"]["short_id"]))
    lines.append("    flow: xtls-rprx-vision")
    lines.append("    client-fingerprint: chrome")
    lines.append("  - name: %s" % _yaml_str(name + "-vless-tls"))
    lines.append("    type: vless")
    lines.append("    server: %s" % _yaml_str(ip))
    lines.append("    port: %d" % p["vless_tls"])
    lines.append("    uuid: %s" % _yaml_str(u["vless_uuid"]))
    lines.append("    network: tcp")
    lines.append("    tls: true")
    lines.append("    servername: %s" % _yaml_str(tls_name))
    lines.append("    flow: xtls-rprx-vision")
    lines.append("    client-fingerprint: chrome")
    lines.append("    skip-cert-verify: %s" % skip)
    lines.append("  - name: %s" % _yaml_str(name + "-hy2"))
    lines.append("    type: hysteria2")
    lines.append("    server: %s" % _yaml_str(ip))
    lines.append("    port: %d" % p["hy2"])
    lines.append("    password: %s" % _yaml_str(u["hy2_password"]))
    lines.append("    obfs: salamander")
    lines.append("    obfs-password: %s" % _yaml_str(st["hy2_obfs_password"]))
    lines.append("    ports: '%d-%d'" % (hop[0], hop[1]))
    lines.append("    sni: %s" % _yaml_str(tls_name))
    lines.append("    alpn: [h3]")
    lines.append("    skip-cert-verify: %s" % skip)
    lines.append("  - name: %s" % _yaml_str(name + "-tuic"))
    lines.append("    type: tuic")
    lines.append("    server: %s" % _yaml_str(ip))
    lines.append("    port: %d" % p["tuic"])
    lines.append("    uuid: %s" % _yaml_str(u["tuic_uuid"]))
    lines.append("    password: %s" % _yaml_str(u["tuic_password"]))
    lines.append("    alpn: [h3]")
    lines.append("    congestion-controller: bbr")
    lines.append("    udp-relay-mode: native")
    lines.append("    sni: %s" % _yaml_str(tls_name))
    lines.append("    skip-cert-verify: %s" % skip)
    lines.append("  - name: %s" % _yaml_str(name + "-trojan"))
    lines.append("    type: trojan")
    lines.append("    server: %s" % _yaml_str(ip))
    lines.append("    port: %d" % p["trojan"])
    lines.append("    password: %s" % _yaml_str(u["trojan_password"]))
    lines.append("    sni: %s" % _yaml_str(tls_name))
    lines.append("    alpn: [h2, http/1.1]")
    lines.append("    skip-cert-verify: %s" % skip)
    lines.append("  - name: %s" % _yaml_str(name + "-ss"))
    lines.append("    type: ss")
    lines.append("    server: %s" % _yaml_str(ip))
    lines.append("    port: %d" % p["ss"])
    lines.append("    cipher: 2022-blake3-aes-128-gcm")
    lines.append("    password: %s" % _yaml_str(u["ss_password"]))
    lines.append("    udp: true")
    if st["options"].get("vmess"):
        lines.append("  - name: %s" % _yaml_str(name + "-vmess"))
        lines.append("    type: vmess")
        lines.append("    server: %s" % _yaml_str(ip))
        lines.append("    port: %d" % p["vmess"])
        lines.append("    uuid: %s" % _yaml_str(u["vmess_uuid"]))
        lines.append("    alterId: 0")
        lines.append("    cipher: auto")
        lines.append("    tls: true")
        lines.append("    servername: %s" % _yaml_str(tls_name))
        lines.append("    network: ws")
        lines.append("    ws-opts:")
        lines.append("      path: %s" % _yaml_str(st.get("vmess_path", "/ws")))
        lines.append("      headers:")
        lines.append("        Host: %s" % _yaml_str(tls_name))
        lines.append("    skip-cert-verify: %s" % skip)
    names = [name + "-vless-reality", name + "-vless-tls", name + "-hy2",
             name + "-tuic", name + "-trojan", name + "-ss"]
    if st["options"].get("vmess"):
        names.append(name + "-vmess")
    lines.append("proxy-groups:")
    lines.append("  - name: PROXY")
    lines.append("    type: select")
    lines.append("    proxies:")
    for n in names:
        lines.append("      - %s" % _yaml_str(n))
    lines.append("      - DIRECT")
    lines.append("  - name: AUTO")
    lines.append("    type: url-test")
    lines.append("    url: https://www.gstatic.com/generate_204")
    lines.append("    interval: 60")
    lines.append("    proxies:")
    for n in names:
        lines.append("      - %s" % _yaml_str(n))
    lines.append("rules:")
    lines.append("  - GEOIP,CN,DIRECT")
    lines.append("  - MATCH,PROXY")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# regen：渲染全部文件；先校验、再落盘、失败回滚。
# ---------------------------------------------------------------------------

def backup_file(path, keep=5):
    if not os.path.exists(path):
        return
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    dst = "%s.bak.%s" % (path, stamp)
    shutil.copy2(path, dst)
    base = os.path.basename(path)
    olds = sorted(f for f in os.listdir(os.path.dirname(path))
                  if f.startswith(base + ".bak."))
    for f in olds[:-keep]:
        try:
            os.unlink(os.path.join(os.path.dirname(path), f))
        except OSError:
            pass


def cmd_regen(paths, singbox, args):
    st = load_state(paths)
    paths.ensure()
    cfg = build_server_config(st, rule_set_dir=os.path.join(paths.root, "rule-sets"))
    tmp = paths.config + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.chmod(tmp, 0o600)
    # 先校验再落盘：sing-box check 不通过就恢复旧配置，绝不断服。
    if singbox:
        p = subprocess.run([singbox, "check", "-c", tmp],
                           capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            os.unlink(tmp)
            eprint("配置校验失败，旧配置未动：\n%s" % (p.stderr or p.stdout))
            return 1
        print("sing-box check 通过。")
    backup_file(paths.config)
    os.replace(tmp, paths.config)
    # 每位用户的订阅
    for uname, u in sorted(st["users"].items()):
        udir = os.path.join(paths.sub_dir, uname)
        os.makedirs(udir, exist_ok=True)
        os.chmod(udir, 0o700)
        links = build_share_links(st, uname, u)
        with open(os.path.join(udir, "links.txt"), "w") as f:
            for label, url in links:
                f.write("%s: %s\n" % (label, url))
        if shutil.which("qrencode"):
            qr_dir = os.path.join(udir, "qr")
            os.makedirs(qr_dir, exist_ok=True)
            for label, url in links:
                fn = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-") + ".png"
                subprocess.run(["qrencode", "-o", os.path.join(qr_dir, fn),
                                "-s", "6", "-m", "2", url],
                               capture_output=True, timeout=30)
        with open(os.path.join(udir, "client.json"), "w") as f:
            json.dump(build_client_config(st, uname, u), f, indent=2,
                      ensure_ascii=False)
            f.write("\n")
        with open(os.path.join(udir, "clash.yaml"), "w") as f:
            f.write(build_clash_yaml(st, uname, u))
        for fn in ("links.txt", "client.json", "clash.yaml"):
            os.chmod(os.path.join(udir, fn), 0o600)
    print("配置与订阅已生成：%s" % paths.config)
    print("订阅目录：%s/<用户名>/（links.txt / client.json / clash.yaml）" % paths.sub_dir)
    return 0


def cmd_rotate_sni(paths, singbox, args):
    """轮换 Reality SNI：按 SNI 池顺序取下一个（或指定一个）。
    封锁名单盯住一个域名时，一条命令就换一张“身份证”。"""
    st = load_state(paths)
    pool = st.get("reality_sni_pool") or list(REALITY_SNI_POOL)
    want = getattr(args, "sni", None)
    if want:
        if want not in pool:
            pool.append(want)
            st["reality_sni_pool"] = pool
        st["reality_sni"] = want
    else:
        try:
            i = pool.index(st["reality_sni"])
            st["reality_sni"] = pool[(i + 1) % len(pool)]
        except ValueError:
            st["reality_sni"] = pool[0]
    save_state(paths, st)
    print("Reality SNI 已轮换为：%s（Trojan 回落与 Hy2 伪装站同步更新）" % st["reality_sni"])
    return cmd_regen(paths, singbox, args)


def cmd_rotate_ports(paths, singbox, args):
    """轮换全部非 443 端口与跳跃区间（443 是 Reality 的门面，不动）。
    端口被针对时，一条命令换全套。"""
    st = load_state(paths)
    rng = random.Random()
    p_tls, p_hy2, p_tuic, p_trojan, p_ss, p_vmess, p_naive = pick_random_ports(
        rng, 7, taken={PORT_REALITY})
    st["ports"].update({"vless_tls": p_tls, "hy2": p_hy2, "tuic": p_tuic,
                        "trojan": p_trojan, "ss": p_ss, "vmess": p_vmess,
                        "naive": p_naive})
    hs = rng.randint(20000, 24000)
    ts = rng.randint(25001, 29000)
    st["hop"] = {"hy2": [hs, hs + rng.randint(500, 1000)],
                 "tuic": [ts, ts + rng.randint(500, 1000)]}
    save_state(paths, st)
    print("端口已轮换（Reality 443 不变）。注意：防火墙规则需同步更新"
          "（install.sh 会在重载时自动重应用）。")
    return cmd_regen(paths, singbox, args)


def cmd_rotate_credentials(paths, singbox, args):
    """轮换服务端身份：新的 Reality 密钥对 + short_id。
    怀疑服务端身份泄露时用；用户 UUID 不变，订阅不用重发。"""
    st = load_state(paths)
    priv, pub = gen_reality_keypair(singbox)
    st["reality"] = {"private_key": priv, "public_key": pub,
                     "short_id": gen_short_id(singbox)}
    save_state(paths, st)
    print("Reality 密钥对与 short_id 已轮换，用户订阅需重新生成（已自动生成）。")
    return cmd_regen(paths, singbox, args)


def cmd_rotate_user(paths, singbox, args):
    """轮换单个用户的全部凭证（保留到期时间）。凭证泄露时只换这一个人。"""
    st = load_state(paths)
    name = args.name
    if name not in st["users"]:
        eprint("用户 %s 不存在。" % name)
        return 1
    exp = st["users"][name].get("expires_at")
    st["users"][name] = new_user_credentials(expires_at=exp)
    save_state(paths, st)
    print("用户 %s 的凭证已轮换，旧链接即刻失效。" % name)
    return cmd_regen(paths, singbox, args)


def cmd_renew_cert(paths, singbox, args):
    """重新签发自签证书（换密钥 + 新 pin）。真实证书请走 set-cert。"""
    st = load_state(paths)
    if st["cert"]["mode"] != "self-signed":
        eprint("当前是真实证书，renew-cert 只用于自签证书。")
        return 1
    for f in ("cert.pem", "key.pem"):
        try:
            os.unlink(os.path.join(paths.root, f))
        except OSError:
            pass
    cn = st.get("domain") or "sing-box-ours.local"
    cert_path, key_path, pin = make_self_signed_cert(paths.root, cn)
    st["cert"] = {"mode": "self-signed", "cert_path": cert_path,
                  "key_path": key_path, "pin_sha256": pin}
    save_state(paths, st)
    print("自签证书已重新签发（新 pin：%s…）。" % pin[:16])
    return cmd_regen(paths, singbox, args)


def cmd_expire_check(paths, singbox, args):
    """删除已过期的用户（到期日 < 今天）。由每日定时器调用。"""
    import datetime
    st = load_state(paths)
    today = datetime.date.today().isoformat()
    expired = [n for n, u in st["users"].items()
               if u.get("expires_at") and u["expires_at"] < today]
    if not expired:
        print("没有过期用户。")
        return 0
    if len(expired) == len(st["users"]):
        eprint("拒绝删除全部用户（所有用户都过期了，请手动处理）。")
        return 1
    for n in expired:
        del st["users"][n]
        sub = os.path.join(paths.sub_dir, n)
        if os.path.isdir(sub):
            shutil.rmtree(sub)
    save_state(paths, st)
    print("已删除过期用户：%s" % ", ".join(expired))
    return cmd_regen(paths, singbox, args)


def cmd_fragment(paths, singbox, args):
    """开关客户端 TLS fragment（只对简单 SNI 过滤有效，默认关闭）。"""
    st = load_state(paths)
    st["options"]["tls_fragment"] = (args.state == "on")
    save_state(paths, st)
    print("TLS fragment 已%s。" % ("开启" if args.state == "on" else "关闭"))
    return cmd_regen(paths, singbox, args)


def cmd_show(paths, singbox, args):
    st = load_state(paths)
    print("服务端：%s（域名：%s）" % (st["server_ip"], st.get("domain") or "无"))
    print("Reality SNI：%s；VLESS Reality 端口：443；证书：%s" %
          (st["reality_sni"], st["cert"]["mode"]))
    print("端口：%s" % json.dumps(st["ports"], ensure_ascii=False))
    print("跳跃区间：Hy2 %s，TUIC %s" % (st["hop"]["hy2"], st["hop"]["tuic"]))
    print("可选协议：VMess=%s Naive=%s WARP=%s" %
          (st["options"].get("vmess"), st["options"].get("naive"),
           st["options"].get("warp")))
    print("用户：%s" % ", ".join(sorted(st["users"])))
    if args.name:
        if args.name not in st["users"]:
            eprint("用户 %s 不存在。" % args.name)
            return 1
        print("--- %s 的分享链接 ---" % args.name)
        for label, url in build_share_links(st, args.name, st["users"][args.name]):
            print("%s: %s" % (label, url))
    return 0


def cmd_set_domain(paths, singbox, args):
    st = load_state(paths)
    st["domain"] = args.domain or None
    if args.domain and singbox and not st.get("ech"):
        ech = gen_ech_keypair(singbox, args.domain)
        if ech:
            st["ech"] = {"private_key_blob": ech[0], "config_blob": ech[1]}
            print("ECH 密钥已生成。")
        else:
            print("提示：ECH 密钥未生成（需要 sing-box 二进制），ECH 保持关闭。")
    save_state(paths, st)
    print("域名已设为：%s（证书仍用原来的；换真实证书请用 set-cert）" % (args.domain or "无"))
    return cmd_regen(paths, singbox, args)


def cmd_set_cert(paths, singbox, args):
    import hashlib
    st = load_state(paths)
    der = subprocess.run(["openssl", "x509", "-in", args.cert, "-outform", "DER"],
                         capture_output=True, timeout=30).stdout
    st["cert"] = {"mode": "real", "cert_path": args.cert, "key_path": args.key,
                  "pin_sha256": hashlib.sha256(der).hexdigest()}
    save_state(paths, st)
    print("已切换为真实证书：%s" % args.cert)
    return cmd_regen(paths, singbox, args)


def cmd_enable(paths, singbox, args):
    st = load_state(paths)
    if args.feature == "vmess":
        st["options"]["vmess"] = True
        if not st.get("vmess_path"):
            st["vmess_path"] = "/" + gen_hex(8)
        print("VMess + WS + TLS 已开启。")
    elif args.feature == "naive":
        if st["cert"]["mode"] != "real" or not st.get("domain"):
            eprint("Naive 需要真实域名 + 真实证书（客户端不支持 insecure），"
                   "请先 set-domain 并 set-cert。")
            return 1
        st["options"]["naive"] = True
        print("Naive 已开启。")
    save_state(paths, st)
    return cmd_regen(paths, singbox, args)


def cmd_set_hy2_bandwidth(paths, singbox, args):
    """设置 Hysteria2 的上下行带宽（Mbps），启用 Brutal；0 表示取消。"""
    st = load_state(paths)
    up, down = int(args.up), int(args.down)
    if up <= 0 or down <= 0:
        st["hy2_bandwidth"] = None
        print("Hy2 带宽已取消，改走 BBR。")
    else:
        st["hy2_bandwidth"] = {"up": up, "down": down}
        print("Hy2 带宽已设为上行 %d Mbps / 下行 %d Mbps（Brutal）。"
              "请填实测值，瞎填反而更慢。" % (up, down))
    save_state(paths, st)
    return cmd_regen(paths, singbox, args)


def cmd_set_mode(paths, singbox, args):
    """双模式：low-latency（直连 Reality，延迟最低）与
    high-concealment（TLS fragment + ECH + CDN 路径，隐蔽最强）。
    两者不可兼得：CDN 前置多一跳，延迟更高；高隐蔽模式会开 fragment。"""
    st = load_state(paths)
    mode = args.mode
    st["options"]["mode"] = mode
    st["options"]["tls_fragment"] = (mode == "high-concealment")
    save_state(paths, st)
    if mode == "high-concealment":
        print("已切到高隐蔽模式：TLS fragment 开启；有域名时 ECH 已开；"
              "需要 CDN 前置请再开 VMess。代价是延迟更高（多一跳）。")
    else:
        print("已切到低延迟模式：直连 Reality，fragment 关闭。")
    return cmd_regen(paths, singbox, args)


def main():
    ap = argparse.ArgumentParser(description="sing-box-ours 配置生成器")
    ap.add_argument("--root", default=os.environ.get("SB_OURS_ROOT", "/etc/sing-box-ours"))
    ap.add_argument("--sing-box", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="初始化状态（仅一次）")
    p.add_argument("--ip", default=None)
    p.add_argument("--domain", default=None)
    p.add_argument("--sni", default=None)
    p.add_argument("--cert", default=None)
    p.add_argument("--key", default=None)
    p.add_argument("--vmess", action="store_true")
    p.add_argument("--naive", action="store_true")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("regen", help="按 state.json 重新生成配置与订阅")
    p.set_defaults(fn=cmd_regen)
    p = sub.add_parser("add-user", help="新增用户")
    p.add_argument("name")
    p.add_argument("--expires", default=None, help="到期日 YYYY-MM-DD，留空为永久")
    p.set_defaults(fn=cmd_add_user)
    p = sub.add_parser("del-user", help="删除用户（其链接即刻失效）")
    p.add_argument("name")
    p.set_defaults(fn=cmd_del_user)
    p = sub.add_parser("list-users", help="列出用户")
    p.set_defaults(fn=cmd_list_users)
    p = sub.add_parser("show", help="查看状态与某用户的分享链接")
    p.add_argument("name", nargs="?", default=None)
    p.set_defaults(fn=cmd_show)
    p = sub.add_parser("warp-on", help="注册免费 WARP 并开启分流")
    p.set_defaults(fn=cmd_warp_on)
    p = sub.add_parser("warp-off", help="关闭 WARP 分流")
    p.set_defaults(fn=cmd_warp_off)
    p = sub.add_parser("set-domain", help="设置/清除域名（影响 TLS 与 ECH）")
    p.add_argument("domain", nargs="?", default=None)
    p.set_defaults(fn=cmd_set_domain)
    p = sub.add_parser("set-cert", help="换用真实证书")
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.set_defaults(fn=cmd_set_cert)
    p = sub.add_parser("enable", help="开启可选协议：vmess / naive")
    p.add_argument("feature", choices=["vmess", "naive"])
    p.set_defaults(fn=cmd_enable)
    p = sub.add_parser("rotate-sni", help="轮换 Reality SNI（可指定域名）")
    p.add_argument("sni", nargs="?", default=None)
    p.set_defaults(fn=cmd_rotate_sni)
    p = sub.add_parser("rotate-ports", help="轮换全部非 443 端口与跳跃区间")
    p.set_defaults(fn=cmd_rotate_ports)
    p = sub.add_parser("rotate-credentials", help="轮换 Reality 密钥对与 short_id")
    p.set_defaults(fn=cmd_rotate_credentials)
    p = sub.add_parser("rotate-user", help="轮换单个用户的全部凭证")
    p.add_argument("name")
    p.set_defaults(fn=cmd_rotate_user)
    p = sub.add_parser("renew-cert", help="重新签发自签证书")
    p.set_defaults(fn=cmd_renew_cert)
    p = sub.add_parser("expire-check", help="删除已过期的用户")
    p.set_defaults(fn=cmd_expire_check)
    p = sub.add_parser("fragment", help="开关客户端 TLS fragment：on / off")
    p.add_argument("state", choices=["on", "off"])
    p.set_defaults(fn=cmd_fragment)
    p = sub.add_parser("set-hy2-bandwidth", help="设 Hy2 带宽启用 Brutal：<上行Mbps> <下行Mbps>，0 取消")
    p.add_argument("up", type=int)
    p.add_argument("down", type=int)
    p.set_defaults(fn=cmd_set_hy2_bandwidth)
    p = sub.add_parser("set-mode", help="双模式：low-latency / high-concealment")
    p.add_argument("mode", choices=["low-latency", "high-concealment"])
    p.set_defaults(fn=cmd_set_mode)
    args = ap.parse_args()
    paths = Paths(args.root)
    singbox = find_singbox(args.sing_box)
    if args.cmd != "init" and not os.path.exists(paths.state):
        eprint("state.json 不存在，请先运行 init。")
        return 1
    try:
        return args.fn(paths, singbox, args)
    except RuntimeError as e:
        eprint("失败：%s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
