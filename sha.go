package goencrypt

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
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
// decodeType represents the print format, and the result is not encrypted by default.
func SHA(length int, content interface{}, decodeType int) (result string, err error) {
	var h hash.Hash
	if length == SHA1 {
		h = sha1.New()
	} else if length == SHA256 {
		h = sha256.New()
	} else if length == SHA512 {
		h = sha512.New()
	} else {
		return "", errors.New("crypto/sha: unsupported hash algorithm")
	}
	switch content.(type) {
	case []byte:
		return shaToString(h, content.([]byte), decodeType)
	default:
		return shaFileToString(h, content.(string), decodeType)
	}
}

func shaFileToString(h hash.Hash, file string, decodeType int) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return shaEncode(h.Sum(nil), decodeType)
}

func shaToString(h hash.Hash, content []byte, decodeType int) (result string, err error) {
	_, err = h.Write(content)
	if err != nil {
		return
	}
	return shaEncode(h.Sum(nil), decodeType)
}

func shaEncode(content []byte, decodeType int) (res string, err error) {
	if decodeType == PrintHex {
		return hex.EncodeToString(content), nil
	}
	if decodeType == PrintBase64 {
		return base64.StdEncoding.EncodeToString(content), nil
	}
	return string(content), nil
}
