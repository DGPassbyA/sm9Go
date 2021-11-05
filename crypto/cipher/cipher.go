package cipher

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"main/util"
	"math"
	"math/big"

	"github.com/pkg/errors"
	"github.com/triplewz/cryptogm/elliptic/sm9curve"
	"github.com/triplewz/cryptogm/sm/sm3"
	"github.com/triplewz/cryptogm/sm/sm4"
	"github.com/xianghuzhao/kdfcrypt"
)

var KDFSalt = []byte{137, 14, 177, 175, 197, 56, 31, 254, 10, 223, 157, 232, 91, 149, 124, 75, 34, 90, 160, 85, 193, 47, 144, 90, 253, 139, 90, 135, 101, 233, 182, 250}

const _ENC_HID byte = 0x01

type EncMasterKey struct {
	Msk *big.Int
	EncMasterPubKey
}

type EncMasterPubKey struct {
	Mpk *sm9curve.G1
}
type EncUserKey struct {
	Sk *sm9curve.G2
}
type hashMode int

const (
	H1 hashMode = iota
	H2
)

func InitEncMasterKey(eMpk string, eMsk ...string) (mke *EncMasterKey) {
	mke = new(EncMasterKey)
	mpk := new(sm9curve.G1)
	mpk_str, err := util.HexStringToBytes(eMpk)
	if err != nil {
		return nil
	}
	_, err = mpk.Unmarshal(mpk_str)
	mke.Mpk = mpk
	if err != nil {
		return nil
	}
	if len(eMsk) == 1 {
		k := new(big.Int)
		k.SetString(eMsk[0], 16)
		msk := new(big.Int).Set(k)
		mke.Msk = msk
	} else {
		mke.Msk = nil
	}
	return
}

func InitEncUserKey(hex_uk string) (uke *EncUserKey) {
	uke = new(EncUserKey)
	sk := new(sm9curve.G2)
	skBytes, err := util.HexStringToBytes(hex_uk)
	if err != nil {
		return nil
	}
	sk.Unmarshal(skBytes)
	uke.Sk = sk
	return uke
}

//hash implements H1(Z,n) or H2(Z,n) in sm9 algorithm.
func Hash(z []byte, n *big.Int, h hashMode) *big.Int {
	//counter
	ct := 1

	hlen := 8 * int(math.Ceil(float64(5*n.BitLen()/32)))

	var ha []byte
	for i := 0; i < int(math.Ceil(float64(hlen/256))); i++ {
		msg := append([]byte{byte(h)}, z...)
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(ct))
		msg = append(msg, buf...)
		hai := sm3.SumSM3(msg)
		ct++
		if float64(hlen)/256 == float64(int64(hlen/256)) && i == int(math.Ceil(float64(hlen/256)))-1 {
			ha = append(ha, hai[:(hlen-256*int(math.Floor(float64(hlen/256))))/32]...)
		} else {
			ha = append(ha, hai[:]...)
		}
	}

	bn := new(big.Int).SetBytes(ha)
	one := big.NewInt(1)
	nMinus1 := new(big.Int).Sub(n, one)
	bn.Mod(bn, nMinus1)
	bn.Add(bn, one)

	return bn
}

//generate rand numbers in [1,n-1].
func RandFieldElement(rand io.Reader, n *big.Int) (k *big.Int, err error) {
	one := big.NewInt(1)
	b := make([]byte, 256/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	nMinus1 := new(big.Int).Sub(n, one)
	k.Mod(k, nMinus1)
	return
}

//generate matser's secret encrypt key.
func EncMasterKeyGen(rand io.Reader) (mke *EncMasterKey, err error) {
	ke, err := RandFieldElement(rand, sm9curve.Order)
	if err != nil {
		return nil, errors.Errorf("gen rand num err:%s", err)
	}
	mke = new(EncMasterKey)
	mke.Msk = new(big.Int).Set(ke)
	mke.Mpk = new(sm9curve.G1).ScalarBaseMult(ke)
	return
}

//generate user's secret encrypt key.
func EncUserKeyGen(mke *EncMasterKey, id []byte) (uke *EncUserKey, err error) {
	hid := _ENC_HID
	id = append(id, hid)
	n := sm9curve.Order
	t1 := Hash(id, n, H1)
	t1.Add(t1, mke.Msk)

	//if t1 = 0, we need to regenerate the master key.
	if t1.BitLen() == 0 || t1.Cmp(n) == 0 {
		return nil, errors.New("need to regen mk!")
	}

	t1.ModInverse(t1, n)

	//t2 = s*t1^-1
	t2 := new(big.Int).Mul(mke.Msk, t1)

	uke = new(EncUserKey)

	uke.Sk = new(sm9curve.G2).ScalarBaseMult(t2)
	return
}

func Encrypt(M, uid2 []byte, mke *EncMasterKey) (C []byte, err error) {
	var hid byte = _ENC_HID
	//step 1:qb = [H1(IDb || hid, n)]P1 + mpk
	n := sm9curve.Order
	uid2h := append(uid2, hid)
	h := Hash(uid2h, n, H1)
	qb := new(sm9curve.G1).ScalarMult(sm9curve.Gen1, h)
	qb.Add(qb, mke.Mpk)

	//step 2: random r -> [1, n-1]
regen:
	r, err := RandFieldElement(rand.Reader, n)
	if err != nil {
		return nil, errors.Errorf("gen rand num failed:%s", err)
	}

	//step 3: c1 = [r]qb
	C1 := new(sm9curve.G1).ScalarMult(qb, r)
	c1Bytes := C1.Marshal()
	//step 4: g = e(mpk, P2)
	g := sm9curve.Pair(mke.Mpk, sm9curve.Gen2)
	//step 5: w = g^r
	w := new(sm9curve.GT).ScalarMult(g, r)
	wBytes := w.Marshal()

	//step 6: kdf get aes-key and encrypt with sm4
	//K1len = aes_key_len = 256 bit
	//K2len = mac_len as you like
	var K1len uint32 = 16
	var K2len uint32 = 16
	kdf, err := kdfcrypt.CreateKDF("argon2id", "m=4096,t=1,p=1")
	if err != nil {
		return nil, errors.Errorf("create kdf failed:%s", err)
	}
	var kdfKey []byte
	kdfKey = append(kdfKey, c1Bytes...)
	kdfKey = append(kdfKey, wBytes...)
	kdfKey = append(kdfKey, uid2...)
	K, err := kdf.Derive(kdfKey, KDFSalt, K1len+K2len)
	K1 := K[:K1len]
	K2 := K[K1len:]
	if err != nil {
		return nil, errors.Errorf("drive kdf failed:%s", err)
	}
	//check K1 == 0
	var zero_count uint32 = 0
	for kc := range K1 {
		if kc == 0 {
			zero_count++
		}
	}
	if zero_count == K1len {
		goto regen
	}
	//encrypt with sm4
	C2, err := sm4.Sm4Cbc(K1, M, sm4.ENC)
	if err != nil {
		return nil, errors.Errorf("sm4 decrypt failed:%s", err)
	}

	//step 7: C3 = MAC(K2, M)
	hm := hmac.New(sha256.New, K2)
	hm.Write(C2)
	//C3 len is always 32 bytes
	C3 := hm.Sum(nil)
	C = append(c1Bytes, C3...)
	C = append(C, C2...)
	return
}

func Decrypt(C, uid2 []byte, uke *EncUserKey) (M []byte, err error) {
	//C1 64bytes || C3(hmac) 32 bytes || C2(ciphertext) ?? bytes
	//step 1: get C1 form C
	C1 := new(sm9curve.G1)
	c1Bytes := C[:64]
	_, err = C1.Unmarshal(c1Bytes)
	if err != nil {
		return nil, errors.Errorf("C1 unmarshal failed: %v", err)
	}

	//step 2: w = e(C1, deb)
	w := sm9curve.Pair(C1, uke.Sk)
	wBytes := w.Marshal()

	//step 3: get key form kdf, decrypt with aes
	var K1len uint32 = 16
	var K2len uint32 = 16
	kdf, err := kdfcrypt.CreateKDF("argon2id", "m=4096,t=1,p=1")
	if err != nil {
		return nil, errors.Errorf("create kdf failed:%s", err)
	}
	//build a new bytes for kdfKey!!
	var kdfKey []byte
	kdfKey = append(kdfKey, c1Bytes...)
	kdfKey = append(kdfKey, wBytes...)
	kdfKey = append(kdfKey, uid2...)
	K, err := kdf.Derive(kdfKey, KDFSalt, K1len+K2len)
	K1 := K[:K1len]
	//check K1 == 0
	var zero_count uint32 = 0
	for kc := range K1 {
		if kc == 0 {
			zero_count++
		}
	}
	if zero_count == K1len {
		return nil, errors.Errorf("sm4 key error:%s", err)
	}
	//decrypt with sm4
	M, err = sm4.Sm4Cbc(K[:K1len], C[96:], sm4.DEC)
	if err != nil {
		return nil, errors.Errorf("sm4 decrypt failed:%s", err)
	}

	//step 4: u = MAC(K2, C2) verify C3 == u
	hm := hmac.New(sha256.New, K[K1len:])
	hm.Write(C[96:])
	//C3 len is always 32 bytes
	u := hm.Sum(nil)
	if !bytes.Equal(u, C[64:96]) {
		return nil, errors.Errorf("MAC verify failed")
	}
	return
}
func genKDFSalt(len uint32) (salt []byte, err error) {
	_, err = kdfcrypt.CreateKDF("argon2id", "m=4096,t=1,p=1")
	if err != nil {
		return nil, errors.Errorf("gen kdf salt failed: %v", err)
	}
	salt, err = kdfcrypt.GenerateRandomSalt(len)
	if err != nil {
		return nil, errors.Errorf("gen kdf salt failed: %v", err)
	}
	return
}
