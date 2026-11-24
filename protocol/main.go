// VEIL 原型 CLI：一个二进制，三种模式。
//
//	veil genkey  --out server.key            生成服务端/客户端静态密钥对（X25519）
//	veil server  --listen 127.0.0.1:8443 --key server.key [--clients clients.txt]
//	veil client  --server 127.0.0.1:8443 --server-pub <hex> --client-key client.key
//	             --message "hello" [--save-ticket ticket.json] [--resume --ticket ticket.json]
//
// 密钥文件是 JSON {"private": "<base64>", "public": "<base64>"}，权限 0600。
// 测试用的密钥现生成、用完即弃，绝不写进文档。
package main

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 密钥文件 / 票据文件
// ---------------------------------------------------------------------------

type keyFile struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

func saveKeyFile(path string, kp *keyPair) error {
	priv := kp.priv.Bytes()
	kf := keyFile{
		Private: base64.StdEncoding.EncodeToString(priv),
		Public:  base64.StdEncoding.EncodeToString(kp.pub.Bytes()),
	}
	data, _ := json.MarshalIndent(kf, "", "  ")
	return os.WriteFile(path, data, 0600)
}

func loadKeyFile(path string) (*keyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, err
	}
	privBytes, err := base64.StdEncoding.DecodeString(kf.Private)
	if err != nil {
		return nil, err
	}
	priv, err := parsePrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	return &keyPair{priv: priv, pub: priv.PublicKey()}, nil
}

func parsePrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(b)
}

type ticketFile struct {
	TicketID  string `json:"ticket_id"`
	Secret    string `json:"secret"`
	Expiry    int64  `json:"expiry_unix"`
	ServerPub string `json:"server_pub_hex"`
}

func saveTicketFile(path string, id, secret []byte, expiry time.Time, serverPubHex string) error {
	tf := ticketFile{
		TicketID:  base64.StdEncoding.EncodeToString(id),
		Secret:    base64.StdEncoding.EncodeToString(secret),
		Expiry:    expiry.Unix(),
		ServerPub: serverPubHex,
	}
	data, _ := json.MarshalIndent(tf, "", "  ")
	return os.WriteFile(path, data, 0600)
}

func loadTicketFile(path string) (id, secret []byte, expiry time.Time, serverPubHex string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, time.Time{}, "", err
	}
	var tf ticketFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return nil, nil, time.Time{}, "", err
	}
	id, err = base64.StdEncoding.DecodeString(tf.TicketID)
	if err != nil {
		return nil, nil, time.Time{}, "", err
	}
	secret, err = base64.StdEncoding.DecodeString(tf.Secret)
	if err != nil {
		return nil, nil, time.Time{}, "", err
	}
	return id, secret, time.Unix(tf.Expiry, 0), tf.ServerPub, nil
}

// ---------------------------------------------------------------------------
// genkey
// ---------------------------------------------------------------------------

func cmdGenkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := fs.String("out", "", "输出密钥文件路径")
	fs.Parse(args)
	if *out == "" {
		return fmt.Errorf("--out 必填")
	}
	kp, err := generateKeyPair()
	if err != nil {
		return err
	}
	if err := saveKeyFile(*out, kp); err != nil {
		return err
	}
	fmt.Printf("public=%s\n", hex.EncodeToString(kp.pub.Bytes()))
	fmt.Printf("key file written: %s (0600, 测试用密钥)\n", *out)
	return nil
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

type server struct {
	key     *keyPair
	allow   map[string]bool // 已登记的客户端公钥（hex）；nil = 允许任何（仅测试用）
	seenEph map[string]time.Time
	seenMu  sync.Mutex
	tickets *ticketStore
}

func loadClientsFile(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m[strings.ToLower(line)] = true
	}
	return m, nil
}

func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8443", "监听地址")
	keyPath := fs.String("key", "", "服务端静态密钥文件")
	clients := fs.String("clients", "", "已登记客户端公钥文件（每行一个 hex），不传则允许任何客户端（仅测试）")
	fs.Parse(args)
	if *keyPath == "" {
		return fmt.Errorf("--key 必填")
	}
	kp, err := loadKeyFile(*keyPath)
	if err != nil {
		return err
	}
	s := &server{key: kp, seenEph: make(map[string]time.Time), tickets: newTicketStore()}
	if *clients != "" {
		s.allow, err = loadClientsFile(*clients)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "[server] authorized clients: %d\n", len(s.allow))
	} else {
		fmt.Fprintln(os.Stderr, "[server] WARNING: no --clients file, any client key accepted (test only)")
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[server] VEIL-v1 listening on %s, server_pub=%s\n", *listen, hex.EncodeToString(kp.pub.Bytes()))
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[server] accept error: %v\n", err)
			continue
		}
		go s.handleConn(conn)
	}
}

// failSilent：握手/传输失败时静默关闭——不写任何字节回客户端。
// 失败原因只写服务端本地 stderr（原型排障用；生产部署须关闭，见 SECURITY.md）。
func (s *server) failSilent(conn net.Conn, err error) {
	fmt.Fprintf(os.Stderr, "[server] silent drop (%s): %v\n", conn.RemoteAddr(), err)
	conn.Close()
}

func (s *server) checkClientAllowed(cPub []byte) error {
	if s.allow == nil {
		return nil
	}
	if !s.allow[strings.ToLower(hex.EncodeToString(cPub))] {
		return fmt.Errorf("client pubkey not authorized")
	}
	return nil
}

func (s *server) checkSeenEph(ePub []byte) error {
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	now := time.Now()
	if t, ok := s.seenEph[string(ePub)]; ok && now.Sub(t) < seenEphWindow {
		return fmt.Errorf("ephemeral pubkey replayed")
	}
	// 惰性清理过期条目，有界
	if len(s.seenEph) > 100000 {
		for k, t := range s.seenEph {
			if now.Sub(t) >= seenEphWindow {
				delete(s.seenEph, k)
			}
		}
	}
	s.seenEph[string(ePub)] = now
	return nil
}

// handleConn：一次连接的完整处理。任何错误都走 failSilent。
func (s *server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTO))

	// ---- 读 Msg1 / 恢复请求（同一条线上字节，试解密区分）----
	payload, err := readMsg(conn, 113, 385)
	if err != nil {
		s.failSilent(conn, err)
		return
	}
	rawW1 := append([]byte{byte(len(payload) >> 8), byte(len(payload))}, payload...)

	ePubBytes := payload[0:32]
	ePub, err := parsePublicKey(ePubBytes)
	if err != nil {
		s.failSilent(conn, err)
		return
	}
	shared1, err := dh(s.key.priv, ePub)
	if err != nil {
		s.failSilent(conn, err)
		return
	}

	var clientPub []byte
	var resumeSecret []byte // 非空 = 0-RTT 恢复路径
	var earlyData [][]byte

	// 先试完整握手 Msg1：CT1 = payload[32:113]
	k1 := derive(shared1, []byte("VEIL-v1|msg1"), []byte("VEIL-v1|msg1|enc"))
	gcm1, _ := newGCM(k1)
	p1, err := gcm1.Open(nil, zeroNonce, payload[32:113], nil)
	if err == nil && len(p1) == 65 && p1[32] == suiteVeilV1 {
		clientPub = p1[0:32]
	} else {
		// 再试 0-RTT 恢复请求：ticket_id = payload[32:48]，CT' = payload[48:129]
		if len(payload) < 129 {
			s.failSilent(conn, fmt.Errorf("msg1 decrypt failed and too short for resume"))
			return
		}
		ticketID := payload[32:48]
		secret := s.tickets.use(ticketID) // 查不到/已用/过期 -> nil；已查到则立即标记 used
		if secret == nil {
			s.failSilent(conn, fmt.Errorf("msg1 decrypt failed and ticket unknown/used/expired"))
			return
		}
		sharedE := shared1
		kAuth := derive(append(append([]byte{}, sharedE...), secret...),
			[]byte("VEIL-v1|0rtt"), []byte("VEIL-v1|0rtt|auth"))
		gcmAuth, _ := newGCM(kAuth)
		p1r, err := gcmAuth.Open(nil, zeroNonce, payload[48:129], nil)
		if err != nil || len(p1r) != 65 || p1r[32] != suiteVeilV1 {
			s.failSilent(conn, fmt.Errorf("resume request decrypt failed"))
			return
		}
		clientPub = p1r[0:32]
		resumeSecret = secret
	}
	if err := s.checkClientAllowed(clientPub); err != nil {
		s.failSilent(conn, err)
		return
	}
	if err := s.checkSeenEph(ePubBytes); err != nil {
		s.failSilent(conn, err)
		return
	}
	cPub, err := parsePublicKey(clientPub)
	if err != nil {
		s.failSilent(conn, err)
		return
	}

	// ---- 0-RTT：先读早期数据帧（k_data），缓存、不交付 ----
	var kData []byte
	if resumeSecret != nil {
		kData = derive(append(append([]byte{}, resumeSecret...), shared1...),
			[]byte("VEIL-v1|0rtt"), []byte("VEIL-v1|0rtt|data"))
		earlyTr, err := newTransport(conn, kData, kData)
		if err != nil {
			s.failSilent(conn, err)
			return
		}
		for {
			ftype, p, err := earlyTr.readFrame()
			if err != nil {
				s.failSilent(conn, fmt.Errorf("early data read failed: %w", err))
				return
			}
			if ftype == frameEarlyEnd {
				break
			}
			if ftype == frameData {
				earlyData = append(earlyData, p)
			}
			// chaff 直接丢弃；其他类型忽略
		}
	}

	// ---- Msg2 ----
	f, err := generateKeyPair()
	if err != nil {
		s.failSilent(conn, err)
		return
	}
	shared2, err := dh(f.priv, ePub)
	if err != nil {
		s.failSilent(conn, err)
		return
	}
	k2 := derive(append(append([]byte{}, shared1...), shared2...),
		[]byte("VEIL-v1|msg2"), []byte("VEIL-v1|msg2|enc"))
	gcm2, _ := newGCM(k2)
	serverRandom := randBytes(16)
	p2 := append(append(append([]byte{}, s.key.pub.Bytes()...), serverRandom...), randBytes(32)...)
	ct2 := gcm2.Seal(nil, zeroNonce, p2, nil)
	w2payload := append(append(append([]byte{}, f.pub.Bytes()...), ct2...), randBytes(int(randBytes(1)[0])%129)...)
	if err := writeMsg(conn, w2payload); err != nil {
		s.failSilent(conn, err)
		return
	}
	rawW2 := append([]byte{byte(len(w2payload) >> 8), byte(len(w2payload))}, w2payload...)

	// ---- Msg3 ----
	payload3, err := readMsg(conn, 80, 208)
	if err != nil {
		s.failSilent(conn, err)
		return
	}
	shared3, err := dh(f.priv, cPub)
	if err != nil {
		s.failSilent(conn, err)
		return
	}
	k3 := derive(append(append(append([]byte{}, shared1...), shared2...), shared3...),
		[]byte("VEIL-v1|msg3"), []byte("VEIL-v1|msg3|enc"))
	gcm3, _ := newGCM(k3)
	p3, err := gcm3.Open(nil, zeroNonce, payload3[0:80], nil)
	if err != nil || len(p3) != 64 {
		s.failSilent(conn, fmt.Errorf("msg3 decrypt failed"))
		return
	}
	transcript := sha256.Sum256(append(append([]byte{}, rawW1...), rawW2...))
	if string(p3[0:32]) != string(transcript[:]) {
		s.failSilent(conn, fmt.Errorf("msg3 transcript mismatch"))
		return
	}

	// ---- 派生传输密钥，进入传输层 ----
	masterSecret := hkdfExtract([]byte("VEIL-v1|master"),
		append(append(append([]byte{}, shared1...), shared2...), shared3...))
	master := hkdfExpand(masterSecret, append([]byte("VEIL-v1|master|"), transcript[:]...), 32)
	kC2S := hkdfExpand(master, []byte("VEIL-v1|c2s"), 32)
	kS2C := hkdfExpand(master, []byte("VEIL-v1|s2c"), 32)
	tr, err := newTransport(conn, kS2C, kC2S)
	if err != nil {
		s.failSilent(conn, err)
		return
	}
	_ = conn.SetDeadline(time.Time{}) // 握手完成，取消握手超时（回环 echo 用；生产应设空闲超时）

	// 0-RTT：先交付缓存的早期数据（回显），再发新票据
	for _, p := range earlyData {
		if err := tr.writeFrame(frameData, p); err != nil {
			return
		}
	}
	// 发会话票据帧
	ticketID, ticketSecret, ticketExpiry := s.tickets.issue()
	ticketPayload := append(append(append([]byte{}, ticketID...), ticketSecret...), uint64Bytes(uint64(ticketExpiry.Unix()))...)
	if err := tr.writeFrame(frameTicket, ticketPayload); err != nil {
		return
	}
	fmt.Fprintf(os.Stderr, "[server] handshake ok with %s (0-RTT=%v, early_frames=%d)\n",
		conn.RemoteAddr(), resumeSecret != nil, len(earlyData))

	// ---- echo 循环：把内层字节原样回显（原型用 echo 代替 sing-box VLESS 入站）----
	for {
		ftype, p, err := tr.readFrame()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[server] transport read failed (%s): %v\n", conn.RemoteAddr(), err)
			return
		}
		switch ftype {
		case frameData:
			if err := tr.writeFrame(frameData, p); err != nil {
				return
			}
		case frameClose:
			return
		default:
			// chaff / 其他：丢弃
		}
	}
}

// ---------------------------------------------------------------------------
// client
// ---------------------------------------------------------------------------

func cmdClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	serverAddr := fs.String("server", "127.0.0.1:8443", "服务端地址")
	serverPubHex := fs.String("server-pub", "", "服务端静态公钥 hex")
	clientKey := fs.String("client-key", "", "客户端静态密钥文件")
	message := fs.String("message", "hello veil", "要发送并回显的明文")
	saveTicket := fs.String("save-ticket", "", "保存会话票据到文件")
	resume := fs.Bool("resume", false, "用票据做 0-RTT 恢复")
	ticketPath := fs.String("ticket", "", "票据文件（--resume 时必填）")
	fs.Parse(args)
	if *serverPubHex == "" || *clientKey == "" {
		return fmt.Errorf("--server-pub 与 --client-key 必填")
	}
	sPubBytes, err := hex.DecodeString(*serverPubHex)
	if err != nil {
		return err
	}
	sPub, err := parsePublicKey(sPubBytes)
	if err != nil {
		return err
	}
	ck, err := loadKeyFile(*clientKey)
	if err != nil {
		return err
	}

	conn, err := net.DialTimeout("tcp", *serverAddr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(handshakeTO))
	recvBytes := 0 // 握手阶段服务端回包字节数（静默丢弃测试用：失败时必须为 0）

	e, err := generateKeyPair()
	if err != nil {
		return err
	}
	shared1, err := dh(e.priv, sPub)
	if err != nil {
		return err
	}

	var resumeSecret, resumeTicketID []byte
	if *resume {
		if *ticketPath == "" {
			return fmt.Errorf("--resume 需要 --ticket")
		}
		var expiry time.Time
		var srvHex string
		resumeTicketID, resumeSecret, expiry, srvHex, err = loadTicketFile(*ticketPath)
		if err != nil {
			return err
		}
		if srvHex != *serverPubHex {
			return fmt.Errorf("ticket 不是发给这个服务端的")
		}
		if time.Now().After(expiry) {
			return fmt.Errorf("ticket 已过期")
		}
	}

	// ---- Msg1 或恢复请求 W1' ----
	var rawW1 []byte
	if *resume {
		kAuth := derive(append(append([]byte{}, shared1...), resumeSecret...),
			[]byte("VEIL-v1|0rtt"), []byte("VEIL-v1|0rtt|auth"))
		gcmAuth, _ := newGCM(kAuth)
		p1 := append(append(append([]byte{}, ck.pub.Bytes()...), suiteVeilV1), randBytes(32)...)
		ct := gcmAuth.Seal(nil, zeroNonce, p1, nil)
		payload := append(append(append([]byte{}, e.pub.Bytes()...), resumeTicketID...), ct...)
		payload = append(payload, randBytes(int(randBytes(1)[0])%257)...)
		if err := writeMsg(conn, payload); err != nil {
			return err
		}
		rawW1 = append([]byte{byte(len(payload) >> 8), byte(len(payload))}, payload...)

		// 0-RTT：立即发早期数据帧 + early-end 帧（不等 Msg2）
		kData := derive(append(append([]byte{}, resumeSecret...), shared1...),
			[]byte("VEIL-v1|0rtt"), []byte("VEIL-v1|0rtt|data"))
		earlyTr, err := newTransport(conn, kData, kData)
		if err != nil {
			return err
		}
		if err := earlyTr.writeFrame(frameData, []byte(*message)); err != nil {
			return err
		}
		if err := earlyTr.writeFrame(frameEarlyEnd, nil); err != nil {
			return err
		}
	} else {
		k1 := derive(shared1, []byte("VEIL-v1|msg1"), []byte("VEIL-v1|msg1|enc"))
		gcm1, _ := newGCM(k1)
		p1 := append(append(append([]byte{}, ck.pub.Bytes()...), suiteVeilV1), randBytes(32)...)
		ct1 := gcm1.Seal(nil, zeroNonce, p1, nil)
		payload := append(append(append([]byte{}, e.pub.Bytes()...), ct1...), randBytes(int(randBytes(1)[0])%257)...)
		if err := writeMsg(conn, payload); err != nil {
			return err
		}
		rawW1 = append([]byte{byte(len(payload) >> 8), byte(len(payload))}, payload...)
	}

	// ---- Msg2 ----
	payload2, err := readMsg(conn, 128, 256)
	if err != nil {
		fmt.Printf("RECV_BYTES=%d\n", recvBytes)
		return fmt.Errorf("handshake failed reading msg2 (server sent nothing or closed): %w", err)
	}
	recvBytes += 2 + len(payload2)
	fPub, err := parsePublicKey(payload2[0:32])
	if err != nil {
		return err
	}
	shared2, err := dh(e.priv, fPub)
	if err != nil {
		return err
	}
	k2 := derive(append(append([]byte{}, shared1...), shared2...),
		[]byte("VEIL-v1|msg2"), []byte("VEIL-v1|msg2|enc"))
	gcm2, _ := newGCM(k2)
	p2, err := gcm2.Open(nil, zeroNonce, payload2[32:128], nil)
	if err != nil || len(p2) != 80 {
		return fmt.Errorf("msg2 decrypt failed")
	}
	if string(p2[0:32]) != string(sPubBytes) {
		return fmt.Errorf("server pubkey mismatch: possible MITM")
	}
	rawW2 := append([]byte{byte(len(payload2) >> 8), byte(len(payload2))}, payload2...)

	// ---- Msg3 ----
	shared3, err := dh(ck.priv, fPub)
	if err != nil {
		return err
	}
	k3 := derive(append(append(append([]byte{}, shared1...), shared2...), shared3...),
		[]byte("VEIL-v1|msg3"), []byte("VEIL-v1|msg3|enc"))
	gcm3, _ := newGCM(k3)
	transcript := sha256.Sum256(append(append([]byte{}, rawW1...), rawW2...))
	p3 := append(append([]byte{}, transcript[:]...), randBytes(32)...)
	ct3 := gcm3.Seal(nil, zeroNonce, p3, nil)
	payload3 := append(append([]byte{}, ct3...), randBytes(int(randBytes(1)[0])%129)...)
	if err := writeMsg(conn, payload3); err != nil {
		return err
	}

	// ---- 传输密钥 ----
	masterSecret := hkdfExtract([]byte("VEIL-v1|master"),
		append(append(append([]byte{}, shared1...), shared2...), shared3...))
	master := hkdfExpand(masterSecret, append([]byte("VEIL-v1|master|"), transcript[:]...), 32)
	kC2S := hkdfExpand(master, []byte("VEIL-v1|c2s"), 32)
	kS2C := hkdfExpand(master, []byte("VEIL-v1|s2c"), 32)
	tr, err := newTransport(conn, kC2S, kS2C)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	fmt.Println("HANDSHAKE_OK")

	if *resume {
		// 0-RTT：服务端先回显缓存的早期数据，再发新票据
		ftype, p, err := tr.readFrame()
		if err != nil {
			return fmt.Errorf("read echo failed: %w", err)
		}
		if ftype != frameData {
			return fmt.Errorf("expected echo data frame, got type %d", ftype)
		}
		fmt.Printf("ECHO=%s\n", string(p))
		if *saveTicket != "" {
			if err := readAndSaveTicket(tr, *saveTicket, *serverPubHex); err != nil {
				return err
			}
		}
	} else {
		// 完整握手：服务端先发票据帧
		if *saveTicket != "" {
			if err := readAndSaveTicket(tr, *saveTicket, *serverPubHex); err != nil {
				return err
			}
		}
		if err := tr.writeFrame(frameData, []byte(*message)); err != nil {
			return err
		}
		ftype, p, err := tr.readFrame()
		if err != nil {
			return fmt.Errorf("read echo failed: %w", err)
		}
		if ftype != frameData {
			return fmt.Errorf("expected echo data frame, got type %d", ftype)
		}
		fmt.Printf("ECHO=%s\n", string(p))
	}
	_ = tr.writeFrame(frameClose, nil)
	return nil
}

func readAndSaveTicket(tr *transport, path, serverPubHex string) error {
	ftype, p, err := tr.readFrame()
	if err != nil {
		return fmt.Errorf("read ticket frame failed: %w", err)
	}
	if ftype != frameTicket || len(p) != 56 {
		return fmt.Errorf("expected ticket frame (56B), got type %d len %d", ftype, len(p))
	}
	expiry := time.Unix(int64(uint64FromBytes(p[48:56])), 0)
	if err := saveTicketFile(path, p[0:16], p[16:48], expiry, serverPubHex); err != nil {
		return err
	}
	fmt.Printf("TICKET_SAVED=%s\n", path)
	return nil
}

func uint64FromBytes(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// ---------------------------------------------------------------------------

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: veil <genkey|server|client> [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = cmdGenkey(os.Args[2:])
	case "server":
		err = cmdServer(os.Args[2:])
	case "client":
		err = cmdClient(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
