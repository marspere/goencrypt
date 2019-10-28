package goencrypt

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strings"
)

type MessageDigest string

// MD5 information summary, the src has two types: []byte or string
// The default return value is 32-bit lowercase.
func MD5(src interface{}) (md MessageDigest, err error) {
	h := md5.New()
	value, ok := src.(string)
	if !ok {
		value1, ok := src.([]byte)
		if !ok {
			return md, errors.New("unsupported type")
		}
		if _, err = h.Write(value1); err != nil {
			return
		}
		md = MessageDigest(hex.EncodeToString(h.Sum(nil)))
		return
	}
	if _, err = h.Write([]byte(value)); err != nil {
		return
	}
	md = MessageDigest(hex.EncodeToString(h.Sum(nil)))
	return
}

func (md MessageDigest) UpperCase32() string {
	return strings.ToUpper(string(md))
}

func (md MessageDigest) UpperCase16() string {
	value := md[8:24]
	return strings.ToUpper(string(value))
}

func (md MessageDigest) LowerCase16() string {
	return string(md[8:24])
}