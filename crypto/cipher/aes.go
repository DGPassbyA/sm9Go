package cipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
)

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

//PKCS5方式补充明文
func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	fillText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, fillText...)
}

//去除填充
func PKCS5UnPadding(plaintext []byte) []byte {
	length := len(plaintext)
	//获取填充的数值
	unPadding := int(plaintext[length-1])
	return plaintext[:(length - unPadding)]
}
func GenerateNonce() []byte {
	nonce := make([]byte, 12)
	_, err := io.ReadFull(rand.Reader, nonce)
	checkErr(err)
	return nonce
}
func AES_Encrypt_GCM(plaintext, key, nonce []byte) []byte {
	if len(key) != 16 && len(key) != 32 {
		log.Fatal("The length must be 16 or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	checkErr(err)

	aesgcm, err := cipher.NewGCM(block)
	checkErr(err)

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext
}
func AES_Decrypt_GCM(ciphertext, key, nonce []byte) []byte {
	block, err := aes.NewCipher(key)
	checkErr(err)

	aesgcm, err := cipher.NewGCM(block)
	checkErr(err)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	checkErr(err)
	return plaintext
}

func AES_Encrypt_CBC(plaintext, key []byte) []byte {
	if len(key) != 16 && len(key) != 32 {
		log.Fatal("The length must be 16 or 32 bytes")
	}
	pre_plaintext := PKCS5Padding(plaintext, aes.BlockSize)
	block, err := aes.NewCipher(key)
	checkErr(err)

	ciphertext := make([]byte, aes.BlockSize+len(pre_plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	checkErr(err)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], pre_plaintext)

	return ciphertext
}

func AES_Decrypt_CBC(ciphertext, key []byte) []byte {
	if len(key) != 16 && len(key) != 32 {
		log.Fatal("The length must be 16 or 32 bytes")
	}
	block, err := aes.NewCipher(key)
	checkErr(err)
	if len(ciphertext) < aes.BlockSize {
		log.Fatal("ciphertext too short")
	}
	//iv不安全，其后才是密文
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		log.Fatal("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	//原地工作
	mode.CryptBlocks(ciphertext, ciphertext)
	return PKCS5UnPadding(ciphertext)
}
