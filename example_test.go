package goencrypt

import "fmt"

const defaultPublicFile = "./testdata/pub.txt"
const defaultPrivateFile = "./testdata/pri.txt"

func ExampleRSAEncryptAndDecrypt() {
	// rsa encryption
	cipher := NewRSACipher(PrintBase64, defaultPublicFile, defaultPrivateFile)
	cipherText, err := cipher.RSAEncrypt([]byte("hello world"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(cipherText)

	// rsa decryption
	plainText, err := cipher.RSADecrypt(cipherText)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(plainText)
}

func ExampleAESEncryptAndDecrypt() {
	// aes decryption
	cipher, err := NewAESCipher([]byte("0123456789asdfgh"), []byte("0123456789asdfgh"), CBCMode, Pkcs7, PrintBase64)
	if err != nil {
		fmt.Println(err)
		return
	}
	cipherText, err := cipher.AESEncrypt([]byte("hello world"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(cipherText)

	// aes decryption
	plainText, err := cipher.AESDecrypt(cipherText)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(plainText)
}

func ExampleDESEncryptAndDecrypt() {
	// des encryption
	cipher := NewDESCipher([]byte("12345678"), []byte(""), ECBMode, Pkcs7, PrintBase64)
	cipherText, err := cipher.DESEncrypt([]byte("hello world"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(cipherText)

	// des decryption
	plainText, err := cipher.DESDecrypt(cipherText)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(plainText)
}

func ExampleTripleDESEncryptAndDecrypt() {
	// triple des encryption
	cipher := NewDESCipher([]byte("12345678abcdefghijklmnop"), []byte("abcdefgh"), CBCMode, Pkcs7, PrintBase64)
	cipherText, err := cipher.TripleDESEncrypt([]byte("hello world"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(cipherText)

	// triple des decryption
	plainText, err := cipher.TripleDESDecrypt(cipherText)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(plainText)
}

func ExampleSHA() {
	result, err := SHA(SHA1, []byte("hello world"), PrintHex)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(result)
}
