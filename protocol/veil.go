// VEIL（帷幕协议）v1 —— 最小原型。
//
// 只用 Go 标准库，不引入任何第三方模块。
// 密码学原件全部是标准构造：
//   - 密钥交换：X25519（crypto/ecdh）
//   - 加密：AES-256-GCM（crypto/aes + cipher.NewGCM）
//   - 密钥派生：RFC 5869 HKDF-SHA256（crypto/hmac + crypto/sha256 手写 Extract/Expand）
//   - 哈希：SHA-256
//
// 自研的只是协议层：握手流程、帧格式、填充、静默丢弃、会话票据。
// 详见 协议规范.md。
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 常量（与 协议规范.md 一致）
// ---------------------------------------------------------------------------

const (
	suiteVeilV1 byte = 0x01 // X25519 + AES-256-GCM + HKDF-SHA256

	// 帧类型
	frameChaff     byte = 0x00
	frameData      byte = 0x01
	frameTicket    byte = 0x02
	frameClose     byte = 0x03
	frameEarlyEnd  byte = 0x04
	maxPlain       int  = 16384 // 数据帧明文上限（含 type/padlen/payload/pad）
	maxFrameWire   int  = maxPlain + 16 + 2
	handshakeTO         = 10 * time.Second
	ticketLifetime      = 600 * time.Second // 票据有效期 600 秒
	seenEphWindow       = 5 * time.Minute   // 临时公钥去重窗口

	// 重密钥触发阈值（任一先到即触发；原型中帧数很少，实际不会触发，
	// 但逻辑已实现，见 transport.rekeyIfNeeded）
	rekeyFrameLimit = 65536
	rekeyByteLimit  = 256 << 20 // 256 MiB
	rekeyTimeLimit  = 900 * time.Second
)

// ---------------------------------------------------------------------------
// HKDF-SHA256（RFC 5869），只用 crypto/hmac + crypto/sha256 手写。
// 对照 RFC 5869 §2.2 (Extract) / §2.3 (Expand)。
// ---------------------------------------------------------------------------

func hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, sha256.Size) // RFC 5869：salt 为空时用 HashLen 个零字节
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int) []byte {
	var out, t []byte
	for i := byte(1); len(out) < length; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		out = append(out, t...)
	}
	return out[:length]
}

// derive = HKDF-Expand(HKDF-Extract(salt, IKM), info, 32)，规范附录 A 的速查表用的就是它。
func derive(ikm, salt, info []byte) []byte {
	return hkdfExpand(hkdfExtract(salt, ikm), info, 32)
}

// ---------------------------------------------------------------------------
// X25519 密钥对
// ---------------------------------------------------------------------------

type keyPair struct {
	priv *ecdh.PrivateKey
	pub  *ecdh.PublicKey
}

func generateKeyPair() (*keyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &keyPair{priv: priv, pub: priv.PublicKey()}, nil
}

func parsePublicKey(b []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(b)
}

func dh(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(pub)
}

// ---------------------------------------------------------------------------
// AES-256-GCM
// ---------------------------------------------------------------------------

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// 握手报文 nonce：12 字节全零（每个握手密钥只用一次，nonce 固定是安全的）。
var zeroNonce = make([]byte, 12)

// frameNonce：4 字节零 + 8 字节大端计数器。
func frameNonce(counter uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], counter)
	return n
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err) // crypto/rand 失败是致命环境问题，不静默吞掉
	}
	return b
}

// ---------------------------------------------------------------------------
// 线上 framing：[uint16 BE len][payload]，len 为 payload 长度。
// ---------------------------------------------------------------------------

func writeMsg(conn net.Conn, payload []byte) error {
	if len(payload) > 0xFFFF {
		return fmt.Errorf("message too large: %d", len(payload))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// readMsg 读一条 [len][payload] 报文；min/max 用于合法性校验，非法直接报错
// （调用方按规范静默关闭，不回任何字节）。
func readMsg(conn net.Conn, minLen, maxLen int) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n < minLen || n > maxLen {
		return nil, fmt.Errorf("bad message length %d (want %d..%d)", n, minLen, maxLen)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ---------------------------------------------------------------------------
// 传输层：双向独立密钥 + nonce 计数器 + 确定性重密钥。
// ---------------------------------------------------------------------------

type transport struct {
	conn     net.Conn
	sendKey  []byte // 本方发送密钥
	recvKey  []byte // 本方接收密钥
	sendCtr  uint64
	recvCtr  uint64
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
	framesTx int
	framesRx int
	bytesTx  int64
	epoch    uint64 // 重密钥轮次
	started  time.Time
	mu       sync.Mutex
}

func newTransport(conn net.Conn, sendKey, recvKey []byte) (*transport, error) {
	sAEAD, err := newGCM(sendKey)
	if err != nil {
		return nil, err
	}
	rAEAD, err := newGCM(recvKey)
	if err != nil {
		return nil, err
	}
	return &transport{
		conn: conn, sendKey: sendKey, recvKey: recvKey,
		sendAEAD: sAEAD, recvAEAD: rAEAD, started: time.Now(),
	}, nil
}

// rekeyIfNeeded：达到阈值时双方按同一确定性规则各自派生新密钥，计数器归零。
// 发送方与接收方各自按自己的帧计数触发，两端计数一致时结果一致。
func (t *transport) rekeySendIfNeeded() error {
	if t.framesTx < rekeyFrameLimit && t.bytesTx < rekeyByteLimit && time.Since(t.started) < rekeyTimeLimit {
		return nil
	}
	t.epoch++
	info := append([]byte("VEIL-v1|rekey|"), uint64Bytes(t.epoch)...)
	t.sendKey = hkdfExpand(t.sendKey, info, 32)
	aead, err := newGCM(t.sendKey)
	if err != nil {
		return err
	}
	t.sendAEAD = aead
	t.sendCtr = 0
	t.framesTx = 0
	t.bytesTx = 0
	return nil
}

func uint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// sealFrame：明文 = type(1) || padlen(1) || payload || pad(padlen 随机字节)。
func (t *transport) sealFrame(ftype byte, payload []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.rekeySendIfNeeded(); err != nil {
		return nil, err
	}
	padLen := 0
	if len(payload) < maxPlain-2 {
		// 0–255 均匀随机填充（不超过明文上限）
		room := maxPlain - 2 - len(payload)
		if room > 255 {
			room = 255
		}
		padLen = int(randBytes(1)[0]) % (room + 1)
	}
	plain := make([]byte, 0, 2+len(payload)+padLen)
	plain = append(plain, ftype, byte(padLen))
	plain = append(plain, payload...)
	plain = append(plain, randBytes(padLen)...)
	ct := t.sendAEAD.Seal(nil, frameNonce(t.sendCtr), plain, nil)
	t.sendCtr++
	t.framesTx++
	t.bytesTx += int64(len(plain))
	return ct, nil
}

// writeFrame：写一帧 [uint16 len][CT]。
func (t *transport) writeFrame(ftype byte, payload []byte) error {
	ct, err := t.sealFrame(ftype, payload)
	if err != nil {
		return err
	}
	return writeMsg(t.conn, ct)
}

// readFrame：读一帧并解密、校验 nonce 严格递增（计数器即期望 nonce 的一部分）。
// 返回 (type, payload)。nonce 不符 / AEAD 失败 / 长度非法均报错，调用方关闭连接。
func (t *transport) readFrame() (byte, []byte, error) {
	ct, err := readMsg(t.conn, 18, maxFrameWire-2)
	if err != nil {
		return 0, nil, err
	}
	plain, err := t.recvAEAD.Open(nil, frameNonce(t.recvCtr), ct, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("frame AEAD open failed (counter %d): %w", t.recvCtr, err)
	}
	t.recvCtr++
	t.framesRx++
	if len(plain) < 2 {
		return 0, nil, errors.New("frame plaintext too short")
	}
	ftype := plain[0]
	padLen := int(plain[1])
	if 2+padLen > len(plain) {
		return 0, nil, errors.New("frame padlen out of range")
	}
	payload := plain[2 : len(plain)-padLen]
	return ftype, payload, nil
}

// ---------------------------------------------------------------------------
// 会话票据（0-RTT）：服务端内存表，单次使用，600 秒过期，重启即失。
// ---------------------------------------------------------------------------

type ticketEntry struct {
	secret []byte
	expiry time.Time
	used   bool
}

type ticketStore struct {
	mu sync.Mutex
	m  map[string]*ticketEntry
}

func newTicketStore() *ticketStore { return &ticketStore{m: make(map[string]*ticketEntry)} }

func (s *ticketStore) issue() (id, secret []byte, expiry time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id = randBytes(16)
	secret = randBytes(32)
	expiry = time.Now().Add(ticketLifetime)
	s.m[string(id)] = &ticketEntry{secret: secret, expiry: expiry}
	return id, secret, expiry
}

// use：查到且未过期未使用则标记 used 并返回 secret；否则返回 nil。
// 注意：先标记 used、后返回 secret——这是防重放的关键顺序。
func (s *ticketStore) use(id []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[string(id)]
	if !ok || e.used || time.Now().After(e.expiry) {
		return nil
	}
	e.used = true
	return e.secret
}
