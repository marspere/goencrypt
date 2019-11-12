package goencrypt

import (
	"crypto/des"
	"errors"
)

func (c *CipherDES) TripleDESEncrypt(plainText []byte) (cipherText string, err error) {
	block, err := des.NewTripleDESCipher(c.Key)
	if err != nil {
		return
	}
	plainData := c.Fill(plainText, block.BlockSize())
	if plainData == nil {
		err = errors.New("unsupported content to be encrypted")
		return
	}
	if err = c.Encrypt(block, plainData); err != nil {
		return
	}
	return c.Encode(), nil
}

func (c *CipherDES) TripleDESDecrypt(cipherText string) (plainText string, err error) {
	cipherData, err := c.Decode(cipherText)
	if err != nil {
		return
	}
	block, err := des.NewTripleDESCipher(c.Key)
	if err != nil {
		return
	}
	if err = c.Decrypt(block, cipherData); err != nil {
		return
	}
	plainData, err := c.UnFill(c.Output)
	if err != nil {
		return "", handleError(err)
	}
	return string(plainData), nil
}
