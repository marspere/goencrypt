package goencrypt

import (
	"crypto/cipher"
	"errors"
)

type Crypto interface {
	Encrypt(plainText []byte) (string, error)
	Decrypt(cipherText string) (string, error)
}

type Cipher struct {
	GroupMode  int
	FillMode   FillMode
	DecodeType int
	Key        []byte
	Iv         []byte
	Output     CipherText
}

func (c *Cipher) Encrypt(block cipher.Block, plainData []byte) (err error) {
	c.Output = make([]byte, len(plainData))
	if c.GroupMode == CBCMode {
		cipher.NewCBCEncrypter(block, c.Iv).CryptBlocks(c.Output, plainData)
		return
	}
	if c.GroupMode == ECBMode {
		c.NewECBEncrypter(block, plainData)
		return
	}
	// todo:
	return
}

func (c *Cipher) Decrypt(block cipher.Block, cipherData []byte) (err error) {
	c.Output = make([]byte, len(cipherData))
	if c.GroupMode == CBCMode {
		cipher.NewCBCDecrypter(block, c.Iv).CryptBlocks(c.Output, cipherData)
		return
	}
	if c.GroupMode == ECBMode {
		c.NewECBDecrypter(block, cipherData)
		return
	}
	// todo:
	return
}

// default print format is base64
func (c *Cipher) Encode() string {
	if c.DecodeType == PrintHex {
		return c.Output.hexEncode()
	} else {
		return c.Output.base64Encode()
	}
}

func (c *Cipher) Decode(cipherText string) ([]byte, error) {
	if c.DecodeType == PrintBase64 {
		return base64Decode(cipherText)
	} else if c.DecodeType == PrintHex {
		return hexDecode(cipherText)
	} else {
		return nil, errors.New("unsupported print type")
	}
}

func (c *Cipher) Fill(plainText []byte, blockSize int) []byte {
	if c.FillMode == PkcsZero {
		return c.FillMode.zeroPadding(plainText, blockSize)
	} else {
		return c.FillMode.pkcs7Padding(plainText, blockSize)
	}
}

func (c *Cipher) UnFill(plainText []byte) ([]byte, error) {
	if c.FillMode == Pkcs7 {
		return c.FillMode.pkcsUnPadding(plainText), nil
	} else if c.FillMode == PkcsZero {
		return c.FillMode.unZeroPadding(plainText), nil
	} else {
		return nil, errors.New("unsupported fill mode")
	}
}

func (c *Cipher) NewECBEncrypter(block cipher.Block, plainData []byte) {
	tempText := c.Output
	for len(plainData) > 0 {
		block.Encrypt(tempText, plainData[:block.BlockSize()])
		plainData = plainData[block.BlockSize():]
		tempText = tempText[block.BlockSize():]
	}
}

func (c *Cipher) NewECBDecrypter(block cipher.Block, cipherData []byte) {
	tempText := c.Output
	for len(cipherData) > 0 {
		block.Decrypt(tempText, cipherData[:block.BlockSize()])
		cipherData = cipherData[block.BlockSize():]
		tempText = tempText[block.BlockSize():]
	}
}
