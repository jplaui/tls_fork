package tls

import (
	"math/big"
	"reflect"
	"testing"
	// bh "go.mau.fi/libsignal/util/bytehelper"
)

var testDataAES128GCM13 = []struct {
	trafficSecret, nonce, ciphertext, additionalData, plaintext string
}{
	{
		"00c37976b9763eb4db5fd2a672941ea5a3fe0e823b8ff027cabc7f031755eeaf",
		"0000000000000003",
		"299f12e2d244445192d96c8b5b90aecd188d80baceb08a4858e7629cb6ffc1be00bd613e2a00791f3f494ab54e7173481f0733d127",
		"1703030035",
		"14000020de1ca1109bfbfe76941ed12e24bfd823dcc49e5fe3236e6a6091d2df5c0ded7f16",
	},
}

// inside folder, execute with: `go test -run TestDecryptAESGCM13 -v .`
func TestDecryptAESGCM13(t *testing.T) {
	for _, test := range testDataAES128GCM13 {

		ts, _ := new(big.Int).SetString(test.trafficSecret, 16)
		n, _ := new(big.Int).SetString(test.nonce, 16)
		c, _ := new(big.Int).SetString(test.ciphertext, 16)
		ad, _ := new(big.Int).SetString(test.additionalData, 16)
		pt, _ := new(big.Int).SetString(test.plaintext, 16)
		trafficSecret := ts.Bytes()
		nonce := n.Bytes()
		ciphertext := c.Bytes()
		additionalData := ad.Bytes()
		plaintextPrime := pt.Bytes()

		plaintext, err := DecryptAESGCM13(trafficSecret, nonce, ciphertext, additionalData)
		if err != nil {
			t.Errorf("aes decrypt error: %s", err)
		}
		t.Log(plaintext)
		t.Log(plaintextPrime)
		if !reflect.DeepEqual(plaintext, plaintextPrime) {
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
