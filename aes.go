package goencrypt

import (
	"crypto/aes"
	"errors"
)

type CipherAES struct {
	Cipher
}

func NewAESCipher(key, iv []byte, groupMode int, fillMode FillMode, decodeType int) *CipherAES {
	return &CipherAES{
		Cipher{
			GroupMode:  groupMode,
			FillMode:   fillMode,
			DecodeType: decodeType,
			Key:        key,
			Iv:         iv,
		},
	}
}

func (c *CipherAES) AESEncrypt(plainText []byte) (cipherText string, err error) {
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return
	}
	plainData := c.Fill(plainText, block.BlockSize())
	if plainData == nil {
		err = errors.New("unsupported content to be encrypted")
		return
	}
	c.Output = make(CipherText, len(plainData))
	if err = c.Encrypt(block, plainData); err != nil {
		return
	}
	return c.Encode(), nil
}

func (c *CipherAES) AESDecrypt(cipherText string) (plainText string, err error) {
	cipherData, err := c.Decode(cipherText)
	if err != nil {
		return
	}
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return
	}
	if len(cipherData)%block.BlockSize() != 0 {
		err = errors.New("cipher text is not a multiple of the block size")
		return
	}
	if err = c.Decrypt(block, cipherData); err != nil {
		return
	}
	plainData, err := c.UnFill(c.Output)
	if err != nil {
		return
	}
	return string(plainData), nil
}
