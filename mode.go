package goencrypt

import "bytes"

const (
	CBCMode = iota
	CFBMode
	CTRMode
	ECBMode
	OFBMode
)

const pk5BlockSize = 8

type FillMode int

const (
	PkcsZero FillMode = iota
	Pkcs5
	Pkcs7
)

func (fm FillMode) pkcs5Padding(plainText []byte) []byte {
	length := len(plainText)
	var paddingText []byte
	if length%pk5BlockSize == 0 {
		paddingText = bytes.Repeat([]byte{byte(pk5BlockSize)}, pk5BlockSize)
	} else {
		paddingSize := pk5BlockSize - len(plainText)%pk5BlockSize
		paddingText = bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	}
	return append(plainText, paddingText...)
}

// The blockSize argument should be 16, 24, or 32.
// Corresponding AES-128, AES-192, or AES-256.
func (fm FillMode) pkcs7Padding(plainText []byte, blockSize int) []byte {
	paddingSize := blockSize - len(plainText)%blockSize
	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(plainText, paddingText...)
}

func (fm FillMode) pkcsUnPadding(plainText []byte) []byte {
	length := len(plainText)
	number := int(plainText[length-1])
	return plainText[:length-number]
}

func (fm FillMode) zeroPadding(plainText []byte, blockSize int) []byte {
	if plainText[len(plainText)-1] == 0 {
		return nil
	}
	paddingSize := pk5BlockSize - len(plainText)%blockSize
	paddingText := bytes.Repeat([]byte{byte(0)}, paddingSize)
	return append(plainText, paddingText...)
}

func (fm FillMode) unZeroPadding(plainText []byte) []byte {
	length := len(plainText)
	count := 1
	for i := length - 1; i > 0; i-- {
		if plainText[i] == 0 && plainText[i-1] == plainText[i] {
			count++
		}
	}
	return plainText[:length-count]
}
