# goencrypt

Go实现的各种加密算法，包括对称密码（DES、3DES、AES）、非对称密码（DH、RSA）等

## Quick Start

Download and install

```bash
go get github.com/marspere/goencrypt
```

```bash
# assume the following codes in example.go file
$ cat example.go
```

```
package main

import "github.com/marspere/goencrypt/md5"

func main() {
	value, err := md5.MD5("hello world")
	if err != nil {
	    fmt.Println(err)
	}
	fmt.Println(value.Value)
	// output: 5eb63bbbe01eeed093cb22bb8f5acdc3
}
```

```bash
# run example.go
$ go run example.go
```

## API Examples

You can find a number of examples at goencrypt repository.

### MD5 Message-Digest Algorithm

It is a widely used cryptographic hash function that produces a hash value to ensure complete and consistent information transfer.

```
func main() {	
    // The return value is 32-bit lowercase.
    value, err := md5.MD5("hello world")
    fmt.Println(value.Value)
    
    // UpperCase32 return 32-bit uppercase value.
    fmt.Println(value.UpperCase32)
    
    // LowerCase16 return 16-bit lowercase value.
    fmt.Println(value.LowerCase16)
    
    // UpperCase16 return 16-bit uppercase value.
    fmt.Println(value.UpperCase16)
}
```
![](image/md5.png)

### RSA Algorithm

RSA encryption algorithm is an asymmetric encryption algorithm. RSA is also a packet encryption algorithm, except that the packet size can be changed according to the size of the key.

RSA encryption limits the length of plaintext, and specifies the maximum length of plaintext to be encrypted = len(key) - 11.

```
func main() {
    cipher := rsa.New(format.PrintBase64, defaultPublicFile, defaultPrivateFile)
	cipherText, err := cipher.RSAEncrypt([]byte("hello world"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(cipherText)
}
```

![](image/rsa_encrypt.png)

### AES Algorithm

AES, Advanced Encryption Standard, also known as Rijndael encryption in cryptography, is a block encryption standard adopted by the US federal government.

AES block length is fixed at 128 bits, the key length can be 128, 192 or 256 bits. It including AES-ECB,AES-CBC,AES-CTR,AES-OFB,AES-CFB.

```
func main() {
    cipher := aes.New([]byte("0123456789asdfgh"), []byte("0123456789asdfgh"), mode.CBCMode, mode.Pkcs5, format.PrintBase64)
	cipherText, err := cipher.AESEncrypt([]byte("hello world"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(cipherText)
}
```

![](image/aes_encrypt.png)

### DES Algorithm

```
func main() {
    cipher := des.New([]byte("12345678"), []byte(""), mode.ECBMode, mode.Pkcs5, format.PrintBase64)
    cipherText, err := cipher.DESEncrypt([]byte("hello world"))
    if err != nil {
    	fmt.Println(err)
    	return
    }
    fmt.Println(cipherText)
}
```

![](image/des_encrypt.png)

### Triple DES Algorithm

```gotemplate
func main() {
	cipher := des.New([]byte("12345678abcdefghijklmnop"), []byte("abcdefgh"), mode.CBCMode, mode.Pkcs5, format.PrintBase64)
	cipherText, err := cipher.TripleDESEncrypt([]byte("hello world"))
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(cipherText)
}
```

![](image/triple_des_encrypt.png)