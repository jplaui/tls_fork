package tls

import (
	"bytes"
	"client/tls_fork/ecdh"
	"client/tls_fork/internal/nistec"
	"crypto/elliptic"
	"errors"
	"fmt"
)

func computeECTF(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, clientKey *ecdh.PrivateKey) error {
	fmt.Println("inside computeECTF...")

	fmt.Println("clientRandom:", clientHello.random)
	fmt.Println("serverRandom:", serverHello.random)

	// pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite) // cipherSuite uint16

	// ecdh package does not provide direct access to computing with elliptic curves
	// thus, using elliptic package to get further access to add, mul, etc...
	// get curveID
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

	// derive some sample keys for testing purposes

	// sample proxy private key
	proxyKey, err := generateECDHEKey(config.rand(), curveID)
	if err != nil {
		return errors.New("proxy generateECDHEKey error")
	}

	// sample server private key
	serverKey, err := generateECDHEKey(config.rand(), curveID)
	if err != nil {
		return errors.New("server generateECDHEKey error")
	}

	// compute client value which is shared with the server

	// merge proxy and client key public keys
	proxyPubKeyX, proxyPubKeyY := elliptic.Unmarshal(curve, proxyKey.PublicKey().Bytes())
	clientPubKeyX, clientPubKeyY := elliptic.Unmarshal(curve, clientKey.PublicKey().Bytes())
	clientProxyPubkeyX, clientProxyPubkeyY := curveParams.Add(clientPubKeyX, clientPubKeyY, proxyPubKeyX, proxyPubKeyY)
	clientProxyPubkey := elliptic.Marshal(curve, clientProxyPubkeyX, clientProxyPubkeyY)

	// paste public key
	pcPubKey, err := clientKey.Curve().NewPublicKey(clientProxyPubkey)
	if err != nil {
		return errors.New("pk parsing failed")
	}

	// server side session key derivation

	// thats a scalar multiplication, the server then uses the x coordinate of the received point and continues
	// ecdh returns x coordinate already.
	// z is the x coordinate which is used in the key derivation function
	z, err := serverKey.ECDH(pcPubKey)
	if err != nil {
		return errors.New("ecdh error")
	}

	// now the second part on the client side
	// now back to client side secret computation, which both client do individually
	// client compute their secret share on top of the server public key

	// server public key ^ client key
	// secret point of client
	p, err := nistec.NewP256Point().SetBytes(serverKey.PublicKey().Bytes())
	if err != nil {
		return errors.New("nistec.NewP256Point().SetBytes() error")
	}
	newP, err := p.ScalarMult(p, clientKey.Bytes())
	if err != nil {
		return errors.New("ScalarMult error")
	}
	proxySecretPublicKey := newP.Bytes()

	// server public client key ^ proxy key
	// secret point of proxy
	p2, err := nistec.NewP256Point().SetBytes(serverKey.PublicKey().Bytes())
	if err != nil {
		return errors.New("nistec.NewP256Point().SetBytes() error")
	}
	newP2, err := p2.ScalarMult(p2, proxyKey.Bytes())
	if err != nil {
		return errors.New("ScalarMult error")
	}
	clientSecretPublicKey := newP2.Bytes()

	// this part is done in 2PC, but tested here to check the math

	// add secret values of client and proxy together which are computed on top of server public key
	proxySecretPublicKeyX, proxySecretPublicKeyY := elliptic.Unmarshal(curve, proxySecretPublicKey)
	clientSecretPublicKeyX, clientSecretPublicKeyY := elliptic.Unmarshal(curve, clientSecretPublicKey)
	addClientSecretsX, addClientSecretsY := curveParams.Add(clientSecretPublicKeyX, clientSecretPublicKeyY, proxySecretPublicKeyX, proxySecretPublicKeyY)
	addClientSecretsPublicKey := elliptic.Marshal(curve, addClientSecretsX, addClientSecretsY)

	// instead of parsing it into a public key, access X coordinate
	p3, err := nistec.NewP256Point().SetBytes(addClientSecretsPublicKey)
	if err != nil {
		return errors.New("nistec.NewP256Point().SetBytes() error")
	}
	xCoord, _ := p3.BytesX()
	// xCoord must be equal to z!

	// the twist here is that 1. adding the client & proxy public keys and 2. scalar multiply the server key on top is equal to
	// having the proxy and client add their secrets on top of the server public key and then add these values together
	// the x coordinate is the same, as in the end the points are the same
	// for the math, of the 3PHS check the files in the folder 3PHS

	// comparison
	if !bytes.Equal(xCoord, z) {
		fmt.Println("3PHS ec computation add up failed")
	}

	// xor
	// z_new := make([]byte, len(z))
	// for i := 0; i < len(z); i++ {
	// 	z_new[i] = z_p[i] ^ z_v[i]
	// }

	// continue to compute ec2f on the client side in 2PC

	return nil
}
