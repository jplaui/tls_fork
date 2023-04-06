package tls

import (
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
	// bh "go.mau.fi/libsignal/util/bytehelper"
)

var testDataAES128GCM13 = []struct {
	trafficSecret, nonce, ciphertext, additionalData, plaintext string
}{
	{
		"349c87d5003e68d39e96426621fdd78e78b1ac6f35d1993e153be5365464cdc9",
		"0000000000000003",
		"a72050f7d03b8bdf234c88712998bf035db9b2a0ec30cb52008edebed46781ccdca0f65b157d20b0ff3404a7363fed666114646b94",
		"1703030035",
		"140000203f7d30ee2f6ba983828e133a45cff2aa2d0dc19b5f7b959db282c5fbc23966d916",
	},
}

// inside folder, execute with: `go test -run TestDecryptAESGCM13 -v .`
func TestDecryptAESGCM13(t *testing.T) {
	for _, test := range testDataAES128GCM13 {

		ts, _ := new(big.Int).SetString(test.trafficSecret, 16)
		nonce, _ := hex.DecodeString(test.nonce)
		c, _ := new(big.Int).SetString(test.ciphertext, 16)
		ad, _ := new(big.Int).SetString(test.additionalData, 16)
		trafficSecret := ts.Bytes()
		ciphertext := c.Bytes()
		additionalData := ad.Bytes()

		// decryption
		plaintext, err := DecryptAESGCM13(trafficSecret, nonce, ciphertext, additionalData)
		if err != nil {
			t.Errorf("aes decrypt error: %s", err)
		}

		// assert equal
		if !reflect.DeepEqual(plaintext, test.plaintext) {
			t.Errorf("aes decrypt failed.")
			return
		}
	}

	t.Log("aes decrypt test passed.")
}

var testDataSHA256 = []struct {
	preimage, hash string
}{
	{
		"39316a73616b6c6a64313239333831303233316131",
		"8c3cbfa579522e522ddc1f593faacb6ce1b3d22a1fcca6abaaaae84e081a04cf",
	},
	{
		"ff",
		"a8100ae6aa1940d0b663bb31cd466142ebbdbd5187131b92d93818987832eb89",
	},
	{
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"af9613760f72635fbdb44a5a0a63c39f12af30f950a6ee5c971be188e89c4051",
	},
}

// inside folder, execute with: `go test -run TestSum256 -v .`
func TestSum256(t *testing.T) {
	for _, test := range testDataSHA256 {

		preimage, _ := new(big.Int).SetString(test.preimage, 16)
		hash, _ := new(big.Int).SetString(test.hash, 16)
		preimageBytes := preimage.Bytes()

		// hashBytes := bh.SliceToArray(hash.Bytes()) // retuns [32]byte slice
		hashBytes := hash.Bytes()
		hashPrime := Sum256(preimageBytes)
		if !reflect.DeepEqual(hashBytes, hashPrime) {
			t.Errorf("sha256 failed.")
			return
		}
	}

	t.Log("sha256 test passed.")
}
