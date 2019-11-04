package goencrypt

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
	"os"
)

const (
	SHA1 = iota
	SHA256
	SHA512
)

// SHA implements several hash functions, including sha1, sha256, and sha512.
// Meanwhile, SHA supports file hash.
// When content type is string, it indicates the address of the file.
func SHA(length int, content interface{}) (result string, err error) {
	var h hash.Hash
	if length == SHA1 {
		h = sha1.New()
	} else if length == SHA256 {
		h = sha256.New()
	} else if length == SHA512 {
		h = sha512.New()
	} else {
		return
	}
	switch content.(type) {
	case []byte:
		return shaToHexString(h, content.([]byte))
	default:
		return shaFileToHexString(h, content.(string))
	}
}

func shaFileToHexString(h hash.Hash, file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func shaToHexString(h hash.Hash, content []byte) (result string, err error) {
	_, err = h.Write(content)
	if err != nil {
		return
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
