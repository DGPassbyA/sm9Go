package test

import (
	"crypto/rand"
	"fmt"
	"main/crypto/cipher"
	"main/crypto/signer"
	"main/util"

	"github.com/triplewz/cryptogm/sm/sm9"
)

func EncryptTest() {
	//产生新的加密主密钥，其中公钥公开
	new_eMk, err := cipher.EncMasterKeyGen(rand.Reader)
	if err != nil {
		fmt.Println(err)
	}
	eMpk1 := new_eMk.EncMasterPubKey
	//以hex形式发布加密主公钥
	var hex_mpk = util.BytesToHexString(eMpk1.Mpk.Marshal())
	fmt.Println("加密主公钥：" + hex_mpk + "\n")
	//生成用户加密密钥对
	var uid1 = []byte("Alice")
	var uid2 = []byte("Bob")
	eUk1, _ := cipher.EncUserKeyGen(new_eMk, uid1)
	eUk2, _ := cipher.EncUserKeyGen(new_eMk, uid2)
	//从16进制加载用户私钥用cipher.InitEncUserKey()
	fmt.Println("Uid1：" + string(uid1) + " 私钥：" + util.BytesToHexString(eUk1.Sk.Marshal()) + "\n")
	fmt.Println("Uid2：" + string(uid2) + " 私钥：" + util.BytesToHexString(eUk2.Sk.Marshal()) + "\n")

	//从hex还原加密主公钥
	eMpk2 := cipher.InitEncMasterKey(hex_mpk)
	//用户1加密数据给用户2
	var msg = []byte("test message")
	ciphertext, _ := cipher.Encrypt(msg, uid2, eMpk2)
	fmt.Printf("msg:'%s' ciphertext: %s\n\n", string(msg), util.BytesToHexString(ciphertext))
	//用户2解密数据
	plaintext, _ := cipher.Decrypt(ciphertext, uid2, eUk2)
	fmt.Printf("plaintext: '%s'", string(plaintext))
}

func SignTest() {
	//产生签名主钥对，其中主公钥公开
	sMpk, _ := sm9.MasterKeyGen(rand.Reader)
	hex_sMpk := util.BytesToHexString(sMpk.Mpk.Marshal())
	fmt.Printf("签名主公钥：%s\n\n", hex_sMpk)
	//生成目标用户
	uid := []byte("Alice")
	uk, _ := sm9.UserKeyGen(sMpk, uid, 0x03)
	uk_hex := util.BytesToHexString(uk.Sk.Marshal())
	fmt.Printf("Uid：%s 私钥：%s\n\n", string(uid), uk_hex)

	//还原签名主公钥
	sMpk2 := signer.InitSignMasterKey(hex_sMpk)
	//还原用户私钥
	uk2 := signer.InitSignUserKey(uk_hex)
	//私钥签名
	msg := []byte("test sign")
	sig, _ := signer.Sign(sMpk2, uk2, msg)
	fmt.Printf("msg: '%s' sign: %s\n\n", string(msg), sig)
	//Bob的id验证
	if !signer.Verify(sMpk2, uid, msg, sig) {
		fmt.Println("Verify failed!")
	} else {
		fmt.Println("Verify pass!")
	}
}
