package csrf

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"go.mkw.re/ghidra-panel/pkg/bitring"
	"strings"
	"time"
)

const csrfValidity = 30 * time.Second

const csrfDepth = 65536

type OneTime struct {
	ring   bitring.BitRing
	macKey [32]byte
}

func NewOneTime() *OneTime {
	c := &OneTime{
		ring: bitring.NewBitRing(csrfDepth),
	}
	if _, randErr := crand.Read(c.macKey[:]); randErr != nil {
		panic("crypto rand read failed: " + randErr.Error())
	}
	return c
}

func (c *OneTime) Issue() string {
	// 0:32 = hmac key
	// 32:40 = counter
	// 40:48 = timestamp
	var key [48]byte

	// issue new key
	n := c.ring.Advance()
	binary.LittleEndian.PutUint64(key[32:40], n)
	binary.LittleEndian.PutUint64(key[40:48], uint64(time.Now().Unix()))

	// hmac key
	mac := hmac.New(sha256.New, c.macKey[:])
	_, _ = mac.Write(key[32:48])
	mac.Sum(key[:0])

	return "v0:" + base64.URLEncoding.EncodeToString(key[:])
}

func (c *OneTime) Check(x string) bool {
	if !strings.HasPrefix(x, "v0:") {
		return false
	}
	x = x[3:]

	var key [48]byte
	_, err := base64.URLEncoding.Decode(key[:], []byte(x))
	if err != nil {
		return false
	}

	// check if expired
	timestamp := binary.LittleEndian.Uint64(key[40:48])
	if time.Now().Unix()-int64(timestamp) > int64(csrfValidity)/int64(time.Second) {
		return false
	}

	// verify hmac key
	var verify [32]byte
	mac := hmac.New(sha256.New, c.macKey[:])
	_, _ = mac.Write(key[32:48])
	mac.Sum(verify[:0])
	macValid := subtle.ConstantTimeCompare(key[:32], verify[:]) == 1

	// check if reused
	reused, ok := c.ring.Insert(binary.LittleEndian.Uint64(key[32:40]))
	return macValid && !reused && ok
}
