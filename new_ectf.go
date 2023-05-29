package tls

import (
	"bytes"
	"client/tls_fork/ecdh"
	"client/tls_fork/internal/nistec"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v4/suites"
)

func computeECTF(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, clientKey *ecdh.PrivateKey) error {
	fmt.Println("inside computeECTF...")

	fmt.Println("clientRandom:", clientHello.random)
	fmt.Println("serverRandom:", serverHello.random)

	// pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite) // cipherSuite uint16

	// check server key
	// fmt.Println("curve:", clientKey.Curve())
	curveID, ok1 := curveIDForCurve(clientKey.Curve())
	if !ok1 {
		return errors.New("cannot get curveID")
	}
	var curve elliptic.Curve
	var ok bool
	if curve, ok = ellipticCurveForCurveID(curveID); curveID != X25519 && !ok {
		return errors.New("tls: server selected unsupported curve")
	}

	// get curve params
	curveParams := curve.Params()

	// proxy private key
	proxyKey, err := generateECDHEKey(config.rand(), curveID)
	if err != nil {
		return errors.New("proxy generateECDHEKey error")
	}

	// for testing purposes only: generate server private key
	// server private key2
	serverKey2, err := generateECDHEKey(config.rand(), curveID)
	if err != nil {
		return errors.New("server generateECDHEKey2 error")
	}

	// compute server public key ^ client key
	// point of proxy
	// c2 := clientKey.Curve()
	p, err := nistec.NewP256Point().SetBytes(serverKey2.PublicKey().Bytes())
	if err != nil {
		return errors.New("c2.newPoint() error")
	}
	newP, err := p.ScalarMult(p, clientKey.Bytes())
	if err != nil {
		return errors.New("ScalarMult error")
	}

	// p, err := c.newPoint().ScalarBaseMult(key.privateKey)
	mypublicKey := newP.Bytes()

	// compute server public client key ^ proxy key
	// point of proxy
	p2, err := nistec.NewP256Point().SetBytes(serverKey2.PublicKey().Bytes())
	if err != nil {
		return errors.New("c2.newPoint() error")
	}
	newP2, err := p2.ScalarMult(p2, proxyKey.Bytes())
	if err != nil {
		return errors.New("ScalarMult error")
	}

	mypublicKey2 := newP2.Bytes()

	ttproxyPubKeyX, ttproxyPubKeyY := elliptic.Unmarshal(curve, mypublicKey)
	ttclientPubKeyX, ttclientPubKeyY := elliptic.Unmarshal(curve, mypublicKey2)
	ttclientProxyPubkeyX, ttclientProxyPubkeyY := curveParams.Add(ttclientPubKeyX, ttclientPubKeyY, ttproxyPubKeyX, ttproxyPubKeyY)
	ttclientProxyPubkey := elliptic.Marshal(curve, ttclientProxyPubkeyX, ttclientProxyPubkeyY)

	p3, err := nistec.NewP256Point().SetBytes(ttclientProxyPubkey)
	if err != nil {
		return errors.New("c2.newPoint() error")
	}

	bs, _ := p3.BytesX()
	fmt.Println("ttclientProxyPubkeyX:", bs)
	// bs must be equal to z!

	fmt.Println("mypublicKey", mypublicKey)
	fmt.Println("mypublicKey2", mypublicKey2)

	// merge proxy and client key
	proxyPubKeyX, proxyPubKeyY := elliptic.Unmarshal(curve, proxyKey.PublicKey().Bytes())
	clientPubKeyX, clientPubKeyY := elliptic.Unmarshal(curve, clientKey.PublicKey().Bytes())
	clientProxyPubkeyX, clientProxyPubkeyY := curveParams.Add(clientPubKeyX, clientPubKeyY, proxyPubKeyX, proxyPubKeyY)
	clientProxyPubkey := elliptic.Marshal(curve, clientProxyPubkeyX, clientProxyPubkeyY)

	// paste public key
	pcPubKey, err := clientKey.Curve().NewPublicKey(clientProxyPubkey)
	if err != nil {
		return errors.New("pk parsing failed 1")
	}

	// server side session key derivation
	// thats a scalar multiplication, the server then uses the x coordinate of the received point and continues
	// ecdh returns x coordinate already.
	z, err := serverKey2.ECDH(pcPubKey)
	if err != nil {
		return errors.New("ecdh error 1")
	}

	// comparison
	if !bytes.Equal(bs, z) {
		fmt.Println("EEEEERRRORR:...")
	}

	// ecdh on y server with secrets from client
	z_p, err := clientKey.ECDH(serverKey2.PublicKey())
	if err != nil {
		return errors.New("ecdh error 1")
	}

	// ecdh on y server with secrets from client
	z_v, err := proxyKey.ECDH(serverKey2.PublicKey())
	if err != nil {
		return errors.New("ecdh error 1")
	}

	// xor
	z_new := make([]byte, len(z))
	for i := 0; i < len(z); i++ {
		z_new[i] = z_p[i] ^ z_v[i]
	}

	suite := suites.MustFind("p256")
	// G := suite.Point().Base()
	z1Scalar := suite.Scalar().SetBytes(z_p)
	z2Scalar := suite.Scalar().SetBytes(z_v)

	z_out := suite.Scalar().Mul(z1Scalar, z2Scalar).String()
	ll, _ := hex.DecodeString(z_out)

	fmt.Println("z", z)
	fmt.Println("z_new", z_new)
	fmt.Println("z_out", ll)
	fmt.Println("z_p", z_p)
	fmt.Println("z_v", z_v)

	return nil
}

func clientComputation() {

}

func proxyCompuation() {

}
