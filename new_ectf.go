package tls

import (
	"bytes"
	"client/tls_fork/ecdh"
	"client/tls_fork/internal/nistec"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/didiercrunch/paillier"
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

	// following deco notation

	// value mappings
	// client has P1 = (x1, y1) and proxy has P2 = (x2, y2)
	// P1 + P2 = (x,y)
	// x = s1 + s2
	x, y := elliptic.Unmarshal(curve, addClientSecretsPublicKey)
	fmt.Println("xCoord and x shoule be equal:", xCoord, x)
	fmt.Println("dont need y", y)
	// use x to verify ectf computation of s1 and s2 values

	x1 := clientSecretPublicKeyX
	y1 := clientSecretPublicKeyY
	x2 := proxySecretPublicKeyX
	y2 := proxySecretPublicKeyY

	// p for modulo computations
	modP := curveParams.P

	// pailier parameters
	paillierParams, err := initPaillier(config.rand())
	if err != nil {
		return errors.New("initPaillier error")
	}

	// compute rho1 at client
	// curveParams.P, config.rand() // curveParams.P is *big.Int
	rho1, err := genRandom(config.rand(), modP)
	if err != nil {
		return errors.New("rho1 genRandom error")
	}

	// turn ec params into big integer numbers
	minusX1 := new(big.Int).Mod(new(big.Int).Neg(x1), modP)
	encryptMinusX1, err := paillierParams.PrivateKey.Encrypt(minusX1, config.rand())
	if err != nil {
		return errors.New("paillier encryption minusX1 error")
	}
	encryptRho1, err := paillierParams.PrivateKey.Encrypt(rho1, config.rand())
	if err != nil {
		return errors.New("paillier encryption rho1 error")
	}
	// access bytes of encrypted paillier value with encryptRho1.C.Bytes()

	// sending paillier public key, bytes of encryptRho1, bytes of minusX1

	// proxy paillier public key parsing
	proxyPaillierPubKey := new(paillier.PublicKey)
	proxyPaillierPubKey.N = new(big.Int).SetBytes(paillierParams.PublicKey.N.Bytes())
	nSquare := proxyPaillierPubKey.GetNSquare()

	// compute rho2 at proxy
	rho2, err := genRandom(rand.Reader, modP)
	if err != nil {
		return errors.New("rho2 genRandom error")
	}
	// proxy rand m generation, we are calling it secretMtaBeta now
	secretMtaBeta, err := genRandom(rand.Reader, modP)
	if err != nil {
		return errors.New("secretMtaBeta genRandom error")
	}

	// parse mta values of client
	parsedEncryptMinusX1 := new(big.Int).SetBytes(encryptMinusX1.C.Bytes())
	parsedEncryptRho1 := new(big.Int).SetBytes(encryptRho1.C.Bytes())

	// vector mta combine encrypted rhos and xX values
	encryptMinusX1Rho2 := new(big.Int).Exp(parsedEncryptMinusX1, rho2, nSquare)
	encryptRho1X2 := new(big.Int).Exp(parsedEncryptRho1, x2, nSquare)
	encryptVec := new(big.Int).Mul(encryptMinusX1Rho2, encryptRho1X2)

	// add encrypted randomness of secretMtaBeta
	// first encrypt secretMtaBeta
	encryptSecretMtaBeta, err := proxyPaillierPubKey.Encrypt(secretMtaBeta, rand.Reader)
	if err != nil {
		return errors.New("encryptSecretMtaBeta proxyPaillierPubKey.Encrypt error")
	}
	// now add to encrypted paillier vector of values
	encryptVec = new(big.Int).Mul(encryptVec, encryptSecretMtaBeta.C)
	// vector modulo operation
	encryptVec = new(big.Int).Mul(encryptVec, nSquare)
	// c2Bytes := encryptVec.Bytes()

	// compute proxy alpha2
	proxyAlpha2 := new(big.Int).Neg(secretMtaBeta)
	proxyAlpha2 = new(big.Int).Mod(proxyAlpha2, modP)

	// computing delta2
	delta2 := new(big.Int).Mul(x2, rho2)
	delta2 = new(big.Int).Add(delta2, proxyAlpha2)
	delta2 = new(big.Int).Mod(delta2, modP)

	// share delta2 with client with delta2.Bytes()

	// at client

	// decrypt encrypted vector of proxy and access clientAlpha1 value
	// parse paillier cipher text
	paillierCypher := new(paillier.Cypher)
	paillierCypher.C = new(big.Int).SetBytes(encryptVec.Bytes())
	clientAlpha1 := paillierParams.PrivateKey.Decrypt(paillierCypher)
	clientAlpha1 = new(big.Int).Mod(clientAlpha1, modP)

	// compute delta1 at client
	delta1 := new(big.Int).Mul(minusX1, rho1)
	delta1 = new(big.Int).Add(delta1, clientAlpha1)
	delta1 = new(big.Int).Mod(delta1, modP)

	// compute delta at client
	delta2client := new(big.Int).SetBytes(delta2.Bytes())
	clientDelta := new(big.Int).Add(delta1, delta2client)
	clientDelta = new(big.Int).Mod(clientDelta, modP)

	// compute delta at proxy
	delta1proxy := new(big.Int).SetBytes(delta1.Bytes())
	proxyDelta := new(big.Int).Add(delta2, delta1proxy)
	proxyDelta = new(big.Int).Mod(proxyDelta, modP)

	if !bytes.Equal(clientDelta.Bytes(), proxyDelta.Bytes()) {
		return errors.New("delta computation failed")
	}

	// compute eta at client and compute new mta c1 values
	deltaInv := new(big.Int).ModInverse(clientDelta, modP)
	eta1 := new(big.Int).Mod(new(big.Int).Mul(rho1, deltaInv), modP)

	// continue to compute ec2f on the client side in 2PC

	return nil
}

func genRandom(random io.Reader, p *big.Int) (*big.Int, error) {
	r, err := rand.Int(random, p)
	if err != nil {
		return nil, err
	}
	// prevent generation of trivial numbers
	zero := big.NewInt(0)
	one := big.NewInt(1)
	if zero.Cmp(r) == 0 || one.Cmp(r) == 0 {
		return genRandom(random, p)
	}
	return r, nil
}

type PaillierParams struct {
	P          *big.Int
	Q          *big.Int
	PrivateKey *paillier.PrivateKey
	PublicKey  *paillier.PublicKey
}

func initPaillier(random io.Reader) (PaillierParams, error) {
	p, err := rand.Prime(random, 1024)
	if err != nil {
		return PaillierParams{}, errors.New("paillier cryptosystem generates prime number p failed")
	}

	q, err := rand.Prime(random, 1024)
	if err != nil {
		return PaillierParams{}, errors.New("paillier cryptosystem generates prime number q failed")
	}

	privKey := paillier.CreatePrivateKey(p, q)
	pubKey := privKey.PublicKey

	return PaillierParams{
		P:          p,
		Q:          q,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

type EC2FParams struct {
	rho                   *big.Int
	eta                   *big.Int
	publicElementInVector *big.Int
	scalarElement         *big.Int
	scalarRandom          *big.Int
	s                     *big.Int
}

type ClientEC2F struct {
	params        *EC2FParams
	mtaPrivateKey *paillier.PrivateKey
}

type ProxyEC2F struct {
	params          *EC2FParams
	mtaPublicKey    *paillier.PublicKey
	mtaRandomSecret *big.Int
	mtaEncryptData  *big.Int
}

func mtaC1() []byte {
	return nil
}

func mtaC2() []byte {
	return nil
}

func mtaFinish() {

}

// ectf in other notation

// step 1.1 https://github.com/tlsnotary/how_it_works/blob/master/how_it_works.md#11-computing-a--y_q2---2y_qy_p--y_p2
// computing A = (y_v^2 - 2*y_v*y_p + y_p^2)
// proxy sends E(y_v^2) and E(-2*Y_v)
// client computes E(y_p^2) and E(A) = E(y_v^2) + E(-2*y_v) * y_p + E(y_p^2)
// client sends E(A*M_a + N_a) and (N_a mod p)
// the randomness is used to prevent the proxy from learning A.

// proxy decrypts and gets (A*M_a + N_a)
// proxy reduces (A*M_a + N_a) mod p

// proxy computes (A*M_a) mod p = (A*M_a + N_a) mod p - N_a mod p

// step 1.2 https://github.com/tlsnotary/how_it_works/blob/master/how_it_works.md#12-computing-b-x_q-x_pp-3
// computing
