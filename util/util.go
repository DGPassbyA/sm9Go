package util

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

func BigIntToHex(n *big.Int) string {
	return fmt.Sprintf("%x", n)
}
func HexToBigInt(s string) *big.Int {
	n := new(big.Int)
	n.SetString(s, 16)
	return n
}

func BytesToHexString(bytes []byte) string {
	return hex.EncodeToString(bytes)
}

func HexStringToBytes(str string) (bytes []byte, err error) {
	bytes, err = hex.DecodeString(str)
	return
}
