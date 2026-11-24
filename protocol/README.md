# VEIL（帷幕协议）原型 — 运行说明

实验版、未经审计。先读 `SECURITY.md`，再跑代码。

## 文件

| 文件 | 说明 |
|---|---|
| `协议规范.md` | 完整规范（中文）：命名、目标、握手、密钥派生、帧格式、填充、重放保护、前向安全、0-RTT、抗探测、sing-box 集成 |
| `SECURITY.md` | 安全声明：已知局限与下一步要做的事 |
| `veil.go` | 协议核心：HKDF-SHA256（手写）、X25519、AES-256-GCM、帧编解码、重密钥、会话票据 |
| `main.go` | CLI：`genkey` / `server` / `client`（一个二进制） |
| `veil_test.go` | 单元测试：RFC 5869 附录 A 向量、帧往返 |
| `test.sh` | 一键测试（见下） |
| `go.mod` | Go 模块：`module veil`，**零第三方依赖** |

## 环境

- Go 1.23+（本机若无 Go：`apt install golang-go`，或从 go.dev 下官方 tarball 解压；本原型用 Go 1.23.4 编译验证）。
- 只用 Go 标准库，不 `go get` 任何东西。`go build` 不联网。

## 一键测试

```bash
bash test.sh
```

测 5 项（全部是真实跑出来的结果，不编造）：

1. 本地回环握手 + echo（发已知明文、收回相同明文；服务端签发票据）；
2. 错误服务端公钥 → 客户端握手失败，且握手阶段服务端回包字节数 `RECV_BYTES=0`（静默丢弃）；
3. 未登记的客户端密钥 → 同样静默丢弃；
4. 明文乱字节探测（HTTP 样式垃圾）→ 服务端不回任何字节；
5. 0-RTT 票据恢复（早期数据原样返回 + 新票据签发），以及同一票据二次使用必须被拒绝。

## 手动跑

```bash
export PATH=$HOME/workspace/tools/go/bin:$PATH   # 若 go 不在 PATH
go build -o /tmp/veil .

/tmp/veil genkey --out server.key   # 打印 public=<hex>，记下来
/tmp/veil genkey --out client.key  # 打印 public=<hex>
echo "<客户端公钥hex>" > clients.txt

/tmp/veil server --listen 127.0.0.1:8443 --key server.key --clients clients.txt
/tmp/veil client --server 127.0.0.1:8443 --server-pub <服务端公钥hex> \
  --client-key client.key --message "hello veil" --save-ticket ticket.json
# 第二次：0-RTT 恢复
/tmp/veil client --server 127.0.0.1:8443 --server-pub <服务端公钥hex> \
  --client-key client.key --message "hello again" \
  --resume --ticket ticket.json --save-ticket ticket2.json
```

## 当前状态（诚实版）

- 已完成：完整握手（Noise IK 式三组 DH + transcript 绑定）、AES-256-GCM 传输帧、随机填充、静默丢弃、临时公钥去重、会话票据 0-RTT（含单次使用强制拒绝）、确定性重密钥逻辑、RFC 5869 向量自检。
- 未完成 / 未验证：重密钥逻辑已写但测试未触发（阈值 65536 帧，测试只有几帧）；chaff 填充帧只定义了类型、原型不主动发送；与 sing-box VLESS 入站的真实集成未做（原型用 echo 代替）；无 fuzz、无第二实现互通、无审计（见 SECURITY.md §5）。
- 测试用密钥现生成、用完即弃，不写进任何文档。
