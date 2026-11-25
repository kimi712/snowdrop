# sing-box-ours：把隐私还给你

> **English:** A self-hosted, open-source, multi-protocol sing-box deployment that returns privacy to you — zero logs by architecture, no accounts, no central provider, everyone runs their own node. One command installs 6 protocols by default (VLESS + Reality, VLESS + TLS, Hysteria2, TUIC, Trojan, Shadowsocks 2022; VMess with one more command, Naive needs a real domain + certificate) with local subscriptions, multi-user management, and automatic rotation. See below (Chinese main text) for details.


> "Arguing that you don't care about the right to privacy because you have nothing to hide is no different than saying you don't care about free speech because you have nothing to say."
> —— Edward Snowden（斯诺登，已核实的名言）

这不是“帮你翻墙”的工具。这是一个**把隐私还给你**的工具。

你每个月给商业 VPN 交钱，换来的是什么？你的全部流量都要经过一家公司的服务器：你去过哪、几点去的、看了什么，全在它手里。它说“无日志”，你只能信它说的。2021 年，一家叫 Kape 的公司花 9.36 亿美元买下 ExpressVPN——它手里同时还有 CyberGhost 和 PIA。你以为在三家之间比价，其实是在同一家店里挑货。

我们的做法反过来：**节点是你自己的，密钥是你自己的，日志是没有的**。一台你自己的 VPS，一个开源脚本，十分钟搭好。从此没有中间商能看到你的流量——因为根本没有中间商。

## 设计哲学（按斯诺登的隐私观）

| 原则 | 落到设计上 |
|---|---|
| **默认零日志** | 生成的服务端配置默认关闭日志（`"log": {"disabled": true}`）。不是“我们承诺不记”，是**架构上就不产生日志**。排障时可临时开 debug，用完关掉。 |
| **开源可审计** | 全部代码公开，谁都能读。没有无源码的黑盒二进制，没有偷偷拉取的第三方脚本，没有藏起来的逻辑。 |
| **不用手机号 / 邮箱注册** | 没有账号体系。凭证全部在本机随机生成，不向任何第三方注册、不上传、不回传。 |
| **元数据也要保护** | ECH 加密 SNI（连“你要去哪”都不明文）；Reality 借真实网站的握手（连“这是代理”都看不出来）；Hysteria2 混淆 + 包大小随机化（连流量长什么样都抹平）。 |
| **去中心化** | 人人自己搭节点。没有一家能被一锅端的服务商，没有一个能被关掉的总开关。你的节点只属于你。 |
| **最小信任** | 每协议独立凭证：一个协议泄露不会牵连其他协议。WARP 注册失败就报错退出，绝不 fallback 到共享密钥。 |

## 这是什么

基于 sing-box v1.14.4（2026-10-24 发布，当前最新稳定版）的一键部署方案：

- **一次安装，6 个协议同时在线**（默认：VLESS Reality、VLESS TLS、Hysteria2、TUIC、Trojan、SS2022；VMess 一条命令开启，Naive 需真实域名+证书），TCP 的 Reality 和 UDP 的 Hysteria2 / TUIC 互为备份，一个被针对了还有别的能用。
- **多用户管理**：每位用户独立凭证，增删用户一条命令；删了用户，他的链接即刻失效。
- **订阅本地生成**：分享链接、sing-box 客户端 JSON、Clash / Mihomo YAML，全部在本机生成，不经过任何第三方订阅转换服务。
- **改配置先校验再重载**：每次生成都调 `sing-box check`，不通过就恢复备份，绝不断服。
- **可选 WARP 分流**：需要解锁的域名走 Cloudflare WARP，其余直连；WARP 账号现场注册，凭证只存本机。

受 [sing-box-yg](https://github.com/yonggekkk/sing-box-yg) 启发的地方只有一个想法本身：**多协议一次装齐**。**本仓库全部代码均为原创**，结构、函数名、实现方式均未照搬上游；上游已知的坑（共享硬编码私钥、`curl --insecure`、行号 sed 改配置、单 UUID 全协议复用、无源码黑盒二进制、防火墙一键全关）在这里全部是反面教材，见下文对照表。

## 协议一览：每个协议都有存在的理由

| 协议 | 角色 | 为什么是它 |
|---|---|---|
| VLESS + Reality + Vision（TCP 443） | **主力** | 借真实大站（默认 apple.com）的 TLS 握手；无正确密钥的探测者看到的就是真网站。Vision 消除 TLS-in-TLS 长度特征。2026 年多方共识中最能存活的组合。 |
| VLESS + TLS + Vision + ECH | **第二主力** | 标准 TLS 路径，可走 CDN；ECH 把 SNI 也加密，防 SNI 字符串匹配封锁。 |
| Hysteria2（UDP，Salamander 混淆 + 端口跳跃） | **速度担当** | QUIC 传输绕开 TCP 限速；混淆把包打成随机噪声；端口跳跃让单端口 UDP 长流限速失效；包大小随机化。 |
| TUIC v5（UDP） | **UDP 备份** | 标准 QUIC、实现简单、客户端支持广；Hy2 被针对时顶上。 |
| Trojan（TCP + fallback） | **兼容担当** | 最简单的 TLS 代理，客户端支持最广；无正确密码的访问者由 fallback 转去真实网站。 |
| Shadowsocks 2022-blake3 | **轻量兼容** | 路由器、电视盒子、旧设备友好。**明确标注：它本身不抗审查，别当主力。** |
| VMess + WS + TLS（可选） | **CDN 路线** | 走 Cloudflare CDN 的那条路；路径是独立随机串，不绑 UUID。默认关闭。 |
| Naive（可选，需真实域名 + 真实证书） | **抗指纹最强** | Chromium 真实握手，官方推荐的 uTLS 替代品。客户端不支持 insecure，所以自签证书时拒绝开启。 |

**刻意没做的**：ShadowsocksR（sing-box 不支持，是占位 stub，启动即报错）；XHTTP / SplitHTTP（sing-box 不支持，走 CDN + XHTTP 请换 Xray/mihomo 核心）；anyTLS（客户端支持窄，相对 Trojan 没有优势）；WireGuard 入站（握手指纹可被检测）；明文 VLESS（可被指纹识别）。

## 延迟：第一优先级

延迟有物理下限——光速＋运营商路由，任何软件都突破不了。**我们能保证的是：代理本身只增加个位数毫秒开销**，端到端延迟由你到服务器的物理距离决定。以下每一项都是为了这个目标：

- **低开销协议**：VLESS（比 VMess 轻，无多余加密开销）、Hysteria2 / TUIC（QUIC/UDP，0-RTT 或 1-RTT 握手，比 TCP+TLS 少往返）、Shadowsocks 2022（快速 AEAD）。默认不叠加多层加密、不走双重代理链。
- **拥塞控制**：服务端安装时按需开启 BBR（内核支持才开，不支持就明说）；Hysteria2 可设上下行带宽启用 Brutal（`set-hy2-bandwidth <上> <下>`，请填实测值，瞎填反而更慢；不设就走 BBR）。多路复用不开——Vision 与复用互斥，且复用省下的握手省不出几毫秒，反而可能加延迟。
- **DNS 要快**：服务端 DNS 用 DoH（1.1.1.1）+ 低延迟 UDP（223.5.5.5，阿里的 DNS，国内解析快）。DNS 解析是常被忽略的延迟大头。
- **自动选最优节点**：客户端配置自带 urltest（每分钟测一次）+ selector 自动选最快出站；分流规则不把流量绕远路（国内直连、广告拦截、AI 站点走 WARP）。
- **可测量**：`install.sh latency` 一键测每个端口的 TCP 建连耗时与 TLS 握手耗时（3 次取中位数），UDP 端口用 ping 作参考。

### 两种模式（不可兼得，如实说明）

| 模式 | 做法 | 延迟代价 |
|---|---|---|
| **低延迟**（默认） | 直连 Reality，不开 fragment | 最低：代理本身个位数毫秒 |
| **高隐蔽** | TLS fragment + ECH + CDN 前置（VMess） | 更高：CDN 前置多一跳，fragment 切分也有开销 |

切换：`install.sh set-mode low-latency` / `install.sh set-mode high-concealment`。不要假装两者兼得——多一跳就是多一跳。

### 自己测延迟

```bash
install.sh latency        # 服务端：逐端口 TCP 建连＋TLS 握手耗时
# 客户端：用 sing-box / Mihomo 自带的 urltest 看每个节点的实测延迟
# 端到端：ping 你的服务器 IP，再对比走代理前后的差值
```

## 安装

一台干净的 VPS（Debian / Ubuntu / Oracle Linux / Rocky / Alma，x86_64 或 ARM64）。**必须用 root 跑**：AWS、甲骨文这些机器默认登录的是 `ubuntu` / `opc` 普通用户，先切到 root 再装：

```bash
sudo -i
```

然后一条命令：

```bash
# 零交互全自动（推荐）：一条命令装完，装完即用
curl -fsSL https://raw.githubusercontent.com/kimi712/snowdrop/main/install.sh | bash -s -- install

# 交互菜单：不带参数，逐步选
curl -fsSL https://raw.githubusercontent.com/kimi712/snowdrop/main/install.sh | bash
```

默认装好：Reality + VLESS-TLS + Hy2 + TUIC + Trojan + SS（VMess、Naive、WARP 默认关闭，按需开启）。装完直接打印默认用户的订阅链接和一键导入码：v2rayN 里按 Ctrl+V，全部节点一次全进。

节点分工（小白看这个就行）：Reality 主用、延迟最低，日常就用它；Hy2 加速、速度最快，下载和看视频用它；TUIC、Trojan、SS、VLESS-TLS 都是备用。

```bash
install.sh show default          # 小白版：节点用途 + 一键导入码（--full 看全部原始链接）
install.sh sub-on                # 开本地订阅：v2rayN 里添加订阅链接，点更新订阅就刷新节点
install.sh sub-off               # 关本地订阅
install.sh add-user alice        # 新增用户（独立凭证）
install.sh del-user alice        # 删除用户（其链接即刻失效）
install.sh warp-on               # 注册免费 WARP 并开启分流
install.sh enable vmess          # 开启 VMess + WS + TLS
install.sh status                # 服务状态 + 配置校验 + 监听端口
install.sh health                # 健康检查
install.sh traffic               # 流量统计（仅端口总字节数，不记访问记录）
install.sh update                # 更新 sing-box 到最新稳定版（校验 SHA-256）
install.sh self-update           # 更新脚本自身到仓库最新版（不动配置）
install.sh latency               # 一键延迟测试（TCP 建连＋TLS 握手耗时）
install.sh rotate-sni            # 轮换 Reality SNI（封锁名单盯上域名时换一张“身份证”）
install.sh rotate-ports          # 轮换全部非 443 端口与跳跃区间
install.sh geo-refresh           # 刷新 geo 规则库
install.sh export / import <文件> # 导出 / 导入全部配置
install.sh uninstall             # 卸载（先备份配置）
install.sh menu                  # 交互菜单
```

订阅文件在 `/etc/sing-box-ours/subscriptions/<用户名>/`：`links.txt`（分享链接）、`sub.b64`（一键导入码，v2rayN 里按 Ctrl+V 直接导）、`client.json`（sing-box 客户端）、`clash.yaml`（Clash / Mihomo）。

## 与 sing-box-yg 的对照

| 维度 | sing-box-yg（上游） | sing-box-ours（我们） |
|---|---|---|
| 协议 | 5 个（无 Trojan / SS / Naive / ECH） | 8 个，含 Trojan / SS2022 / Naive / ECH |
| 凭证 | 单 UUID 全协议复用 | 每协议独立凭证 |
| 配置修改 | 行号 sed（模板一变就错位） | Python 按结构生成 + `sing-box check` + 备份回滚 |
| 日志 | 默认开日志 | 默认关闭日志（零日志是架构） |
| WARP 失败时 | 硬编码共享私钥兜底 | 报错退出，绝不 fallback |
| 下载校验 | 部分 `--insecure`、无哈希 | 全程校验 SHA-256，无 `--insecure` |
| 黑盒二进制 | 有（sbwpph，无源码） | 无 |
| 防火墙 | 一键全关、卸载清空全部 NAT | 只动自己建的 nft 表 |
| 多用户 | 无 | 有（增删、独立凭证、即刻吊销） |
| 订阅 | GitLab token 明文进 URL / 本地纯 HTTP | 本地文件，权限 600；不经过第三方转换 |
| 订阅吊销 | 只能换 UUID 全量作废 | 删用户即吊销 |
| 流量统计 | 无 | 有（仅端口字节数，不记访问记录） |
| 自动更新 | 脚本自更新 `--insecure` | 每周定时器查官方 Releases，校验 SHA-256 |
| 内核 | 双模板（1.10 / 新）行号耦合 | 单一目标版本 v1.14.4，升级即整体重生成 |
| 端口跳跃 | iptables DNAT + 链接 mport | nft DNAT + 客户端 server_ports（冒号区间）+ hop_interval |
| 部署方式 | 交互式菜单一步步选 | 一条命令零交互全自动装完（同时保留交互菜单）；装完即用 |
| 客户端全套 | 链接＋二维码＋订阅（无 Clash YAML 细节） | 分享链接＋sing-box JSON＋Clash/Mihomo YAML＋二维码 PNG（每协议一张） |
| 用户到期管理 | 无 | add-user --expires + 每日 expire-check 定时器自动删过期用户 |
| 配置导出导入 | 无 | export / import（tar.gz，权限 600，导入失败自动恢复备份） |
| 轮换（比封锁跑得快） | 改端口/改 UUID（行号 sed） | rotate-sni / rotate-ports / rotate-credentials / rotate-user，一条命令换全套 |
| 智能分流 | geosite 分流（仅 1.10.7 内核） | 本地 .srs 规则库：广告拦截＋国内直连＋AI 站点走 WARP；每周自动刷新 |
| 双栈 | 有双栈处理 | listen 自动判 IPv6（有则 ::，无则 0.0.0.0），订阅与分流双栈 |
| 延迟 | 无专项设计 | BBR（按需）+ Brutal（按需）+ urltest 自动选优 + 一键 latency 测试 + 双模式 |
| 自愈 | 每日 01:00 重启 | 健康检查＋systemd 失败自动重启＋每周自动更新＋每周规则库刷新＋每日到期检查 |
| 证书续期 | 依赖外部 acme-yg | 自签证书一键 renew-cert；真实证书走用户自带（ACME 内置暂未做，见局限） |
| ECH | 无 | 有（域名模式下自动生成密钥对） |

## 安全与局限（说实话）

- **没有任何协议能保证长期有效。** 审查在升级，对抗也在升级。我们的策略是“多协议并行 + 快速换协议”，不是“一个协议用到老”。如果某个协议某天在你那里不通了，先换协议，再换端口，最后换 SNI 域名——脚本都留了口子。
- **ECH 有局限**：ECH 密钥要从 DNS HTTPS 记录获取，而中国、伊朗正是通过审查加密 DNS 来中和 ECH；俄罗斯直接审查带 ECH 的 ClientHello。ECH 是加分项，不是银弹。
- **uTLS 我们只用 chrome 指纹，且不把它当抗审查手段**：官方明确不推荐 uTLS 抗审查（架构局限、维护不善），指纹本身会过期（1.14.4 的 chrome 仍是 Chrome 133）。真正抗指纹的是真实握手（Reality、Naive、Hy2 的 Chrome QUIC 模仿）。
- **Shadowsocks 2022 不抗审查**：GFW 自 2019 年起可检测 Shadowsocks，2021 年起对热门数据中心流量实时封锁全加密流量。SS2022 只给确实需要它的设备用。
- **自签证书 vs 真实证书**：默认自签（客户端用 insecure / pinSHA256），方便但不够体面；有域名请换真实证书（`set-cert`），Trojan / VMess / Naive 的体验会好得多。Naive 只接受真实证书。
- **ACME 自动发证暂未内置**：sing-box 1.14 已废弃内联 ACME（1.16 将移除），新的 certificate provider 写法尚未核实，v1 不内置，改用自带证书。后续核实后再加。
- **WARP 是 Cloudflare 的免费服务**：注册的是你自己的账号，凭证只存本机；Cloudflare 的政策随时可能变，分流规则请按需调整。

## 文件清单

| 文件 | 作用 |
|---|---|
| `install.sh` | 一键安装 / 更新 / 卸载 / 管理入口 |
| `gen-config.py` | 配置与订阅生成器（Python 标准库，无第三方依赖） |
| `README.md` | 本文件 |
| `原理.md` | 每个反封锁技术的大白话原理 |
| `protocol/` | 我们自己的加密传输协议：规范＋Go 原型＋安全声明（实验版） |
| `上线公告草稿.md` | 上线公告草稿（等定稿再发） |
| `LICENSE` | MIT |
| `VERSION` | 版本号 |

## 版本

见 `VERSION`。目标 sing-box v1.14.4（2026-10-24）。升级 sing-box 版本时，先在测试环境跑 `sing-box check`，再发布。
