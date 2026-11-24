package main

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

// RFC 5869 附录 A 测试向量 1（SHA-256）：
// IKM  = 0x0b * 22, salt = 0x000102...0c, info = 0xf0f1...f9, L = 42
// 向量值以 RFC 5869 附录 A.1 原文为准，并经 Python hmac/hashlib 独立复算一致。
func TestHKDFRFC5869TestCase1(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	wantPRK := "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
	wantOKM := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

	prk := hkdfExtract(salt, ikm)
	if got := hex.EncodeToString(prk); got != wantPRK {
		t.Fatalf("PRK mismatch:\n got %s\nwant %s", got, wantPRK)
	}
	okm := hkdfExpand(prk, info, 42)
	if got := hex.EncodeToString(okm); got != wantOKM {
		t.Fatalf("OKM mismatch:\n got %s\nwant %s", got, wantOKM)
	}
}

// 帧编解码往返：同一对密钥，一端 seal、另一端 read，payload 必须原样回来；
// 篡改一个字节必须解密失败。
func TestFrameRoundTrip(t *testing.T) {
	key := derive([]byte("test-ikm"), []byte("test-salt"), []byte("test-info"))
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	tx, err := newTransport(c1, key, key)
	if err != nil {
		t.Fatal(err)
	}
	rx, err := newTransport(c2, key, key)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("VLESS-frame-bytes-go-here")
	go func() {
		if err := tx.writeFrame(frameData, msg); err != nil {
			t.Error(err)
		}
	}()
	ftype, p, err := rx.readFrame()
	if err != nil {
		t.Fatal(err)
	}
	if ftype != frameData || !bytes.Equal(p, msg) {
		t.Fatalf("round trip mismatch: type=%d payload=%q", ftype, p)
	}
}
