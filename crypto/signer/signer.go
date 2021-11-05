package signer

import (
	"main/util"
	"math/big"

	"github.com/triplewz/cryptogm/elliptic/sm9curve"
	"github.com/triplewz/cryptogm/sm/sm9"
)

const _SIGN_HID byte = 0x03

// type SignMasterKey *sm9.MasterKey
// type SignUserKey *sm9.UserKey

func InitSignMasterKey(hex_mpk string, hex_msk ...string) (k *sm9.MasterKey) {
	k = new(sm9.MasterKey)
	k.Mpk = GetMPK(hex_mpk)
	if len(hex_msk) == 1 {
		k.Msk = GetMSK(hex_msk[0])
	} else {
		k.Msk = nil
	}
	return
}

func InitSignUserKey(hex_uk string) (k *sm9.UserKey) {
	skBytes, err := util.HexStringToBytes(hex_uk)
	if err != nil {
		return
	}
	k = new(sm9.UserKey)
	sk := new(sm9curve.G1)
	_, err = sk.Unmarshal(skBytes)
	if err != nil {
		return
	}
	k.Sk = sk
	return
}
func UserKeyToString(k *sm9.UserKey) string {
	msh_key := k.Sk.Marshal()
	encodedStr := util.BytesToHexString(msh_key)
	return encodedStr
}
func Register(k *sm9.MasterKey, uid []byte) (str_key string, err error) {
	uk, err := sm9.UserKeyGen(k, uid, _SIGN_HID)
	if err != nil {
		return
	}
	msh_key := uk.Sk.Marshal()
	str_key = util.BytesToHexString(msh_key)
	return
}
func Sign(mk *sm9.MasterKey, uk *sm9.UserKey, msg []byte) (sign string, err error) {
	sig, err := sm9.Sign(uk, &mk.MasterPubKey, msg)
	if err != nil {
		return
	}
	sign = util.BigIntToHex(sig.H) + util.BytesToHexString(sig.S.Marshal())
	return
}
func Verify(mk *sm9.MasterKey, uid, msg []byte, sign string) bool {
	sig := new(sm9.Sm9Sig)
	sig.H = util.HexToBigInt(sign[:64])
	sigS := new(sm9curve.G1)
	sigS_str, err := util.HexStringToBytes(sign[64:])
	if err != nil {
		return false
	}
	_, err = sigS.Unmarshal(sigS_str)
	if err != nil {
		return false
	}
	sig.S = sigS
	if sm9.Verify(sig, msg, uid, _SIGN_HID, &mk.MasterPubKey) {
		return true
	}
	return false
}

func GetMSK(hex_msk string) (msk *big.Int) {
	k := new(big.Int)
	k.SetString(hex_msk, 16)
	msk = new(big.Int).Set(k)
	return
}

func GetMPK(hex_mpk string) (mpk *sm9curve.G2) {
	mpk = new(sm9curve.G2)
	mpk_str, err := util.HexStringToBytes(hex_mpk)
	if err != nil {
		return
	}
	_, err = mpk.Unmarshal(mpk_str)
	if err != nil {
		return
	}
	return
}
