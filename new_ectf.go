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

	fmt.Println("z:", z)
	fmt.Println("xCoord:", xCoord)

	// compute new x cord
	// testPubKey, err := clientKey.Curve().NewPublicKey(addClientSecretsPublicKey)
	// if err != nil {
	// 	return errors.New("pk parsing failed")
	// }
	xtest, ytest := elliptic.Unmarshal(curve, serverKey.PublicKey().Bytes())

	// x, y := elliptic.Unmarshal(curve, peerPublicKey)
	// if x == nil {
	// 	return nil
	// }

	xShared, yShared := curve.ScalarMult(xtest, ytest, clientKey.Bytes())
	sharedKeyX := make([]byte, (curve.Params().BitSize+7)/8)
	sharedKeyY := make([]byte, (curve.Params().BitSize+7)/8)
	xShared.FillBytes(sharedKeyX)
	yShared.FillBytes(sharedKeyY)

	// xBs, _ := hex.DecodeString(xtest.String())
	fmt.Println("x1:", xShared)
	fmt.Println("y1:", yShared)

	x1 := new(big.Int).SetBytes(sharedKeyX)
	y1 := new(big.Int).SetBytes(sharedKeyY)

	xShared2, yShared2 := curve.ScalarMult(xtest, ytest, proxyKey.Bytes())
	sharedKeyX2 := make([]byte, (curve.Params().BitSize+7)/8)
	sharedKeyY2 := make([]byte, (curve.Params().BitSize+7)/8)
	xShared2.FillBytes(sharedKeyX2)
	yShared2.FillBytes(sharedKeyY2)

	x2 := new(big.Int).SetBytes(sharedKeyX2)
	y2 := new(big.Int).SetBytes(sharedKeyY2)

	fmt.Println("x2:", xShared)
	fmt.Println("y2:", yShared)

	// added := new(big.Int).Mod(new(big.Int).Add(x1, x2), curveParams.P)
	// bs, _ := hex.DecodeString(added.String())
	// fmt.Println("bs:", bs)

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
	// x, y := elliptic.Unmarshal(curve, addClientSecretsPublicKey)
	// xBs, _ := hex.DecodeString(x.String())
	// fmt.Println("xCoord and x should not be equal:", xCoord, xBs)
	// fmt.Println("dont need y", y)
	// use x to verify ectf computation of s1 and s2 values

	// x1 = clientSecretPublicKeyX
	// y1 = clientSecretPublicKeyY
	// x2 = proxySecretPublicKeyX
	// y2 = proxySecretPublicKeyY

	// @client, set client to party 1
	clientEc2fParty, err := createEc2fParty1(x1, y1, curveParams.P, rand.Reader)
	if err != nil {
		return errors.New("createEc2fParty1 error")
	}

	// @proxy, set proxy to party 2
	proxyEc2fParty, err := createEc2fParty2(x2, y2, curveParams.P, rand.Reader)
	if err != nil {
		return errors.New("createEc2fParty2 error")
	}

	// @client, compute mta message 1
	cipher1, err := clientEc2fParty.MtaEncrypt(
		clientEc2fParty.Params.XShare,
		clientEc2fParty.Params.RhoShare,
	)
	if err != nil {
		return errors.New("MtaEncrypt(XShare, RhoShare) error")
	}

	// @client, create msg1
	msg1 := ec2fMtaMsg1{
		HePublicKey: clientEc2fParty.GetHePubKeyBytes(),
		Cipherdata:  cipher1,
	}

	// msg1 send to proxy

	// @proxy, process msg 1 and compute mta msg 2
	err = proxyEc2fParty.SetHePublicKey(msg1.HePublicKey)
	if err != nil {
		return errors.New("SetHePublicKey(HePublicKey)")
	}

	// @proxy, evaluate mta data
	cipher2, err := proxyEc2fParty.MtaEvaluate(
		msg1.Cipherdata,
		proxyEc2fParty.Params.RhoShare,
		proxyEc2fParty.Params.XShare,
	)
	if err != nil {
		return errors.New("MtaEvaluate(HePublicKey, Cipherdata, RhoShare, XShare) error")
	}

	// @proxy, compute delta share
	err = proxyEc2fParty.ComputeLinearShare(0)
	if err != nil {
		return errors.New("ComputeLinearShare(0) error")
	}

	// @proxy, create msg2
	msg2 := ec2fMtaMsg2{
		Cipherdata: cipher2,
		DeltaShare: proxyEc2fParty.Params.LinearShare.Bytes(),
	}

	// msg2 send to client

	// @client, compute mta share and set in params
	err = clientEc2fParty.ComputeMtaShare(msg2.Cipherdata)
	if err != nil {
		return errors.New("client ComputeMtaShare(msg2.Cipherdata) error")
	}

	// @client, compute linear share and decide on case
	err = clientEc2fParty.ComputeLinearShare(0)
	if err != nil {
		return errors.New("client ComputeLinearShare(0) error")
	}

	// @client, process msg 2 and exchange deltaShare with next mta msg1
	err = clientEc2fParty.ComputeEtaShare(msg2.DeltaShare)
	if err != nil {
		return errors.New("client ComputeEtaShare() error")
	}

	// @client, compute msg3
	cipher1, err = clientEc2fParty.MtaEncrypt(
		clientEc2fParty.Params.YShare,
		clientEc2fParty.Params.EtaShare,
	)
	if err != nil {
		return errors.New("MtaEncrypt(YShare, EtaShare) error")
	}
	msg3 := ec2fMtaMsg3{
		Cipherdata: cipher1,
		DeltaShare: clientEc2fParty.Params.LinearShare.Bytes(),
	}

	// msg3 send to proxy

	// @proxy, derive etaShare
	err = proxyEc2fParty.ComputeEtaShare(msg3.DeltaShare)
	if err != nil {
		return errors.New("proxy ComputeEtaShare() error")
	}

	// @proxy, derive etaShare and evaluate mta2
	cipher2, err = proxyEc2fParty.MtaEvaluate(
		msg3.Cipherdata,
		proxyEc2fParty.Params.EtaShare,
		proxyEc2fParty.Params.YShare,
	)
	if err != nil {
		return errors.New("MtaEvaluate(HePublicKey, Cipherdata, EtaShare, YShare) error")
	}

	// @proxy, compute lambda share
	err = proxyEc2fParty.ComputeLinearShare(1)
	if err != nil {
		return errors.New("ComputeLinearShare(1) error")
	}

	// @proxy, create msg4
	msg4 := ec2fMtaMsg4{
		Cipherdata:  cipher2,
		LambdaShare: proxyEc2fParty.Params.LinearShare.Bytes(),
	}

	// msg4 send to client

	// @client, compute mta share and set in params
	err = clientEc2fParty.ComputeMtaShare(msg4.Cipherdata)
	if err != nil {
		return errors.New("client ComputeMtaShare(msg4.Cipherdata) error")
	}

	// @client, compute linear share and decide on case
	err = clientEc2fParty.ComputeLinearShare(1)
	if err != nil {
		return errors.New("client ComputeLinearShare(1) error")
	}
	// now, lambda correctly set at both parties at linearShare param

	// @client, compute scalar mta encryption
	cipher1, err = clientEc2fParty.MtaEncrypt(
		clientEc2fParty.Params.LinearShare,
	)
	if err != nil {
		return errors.New("MtaEncrypt(LinearShare) error")
	}

	// @client, build last message
	msg5 := ec2fMtaMsg5{
		Cipherdata: cipher1,
	}

	// msg5 send to proxy

	// @proxy, evaluate last scalar mta message
	cipher2, err = proxyEc2fParty.MtaEvaluate(
		msg5.Cipherdata,
		proxyEc2fParty.Params.LinearShare,
	)
	if err != nil {
		return errors.New("MtaEvaluate(HePublicKey, Cipherdata, EtaShare, YShare) error")
	}

	// @proxy, compute SShare
	err = proxyEc2fParty.ComputeSShare()
	if err != nil {
		return errors.New("proxy ComputeSShare() error")
	}

	// @proxy, return msg6
	msg6 := ec2fMtaMsg6{
		Cipherdata: cipher2,
	}

	// msg5 send to client

	// @client, decrypt scalar mta msg
	err = clientEc2fParty.ComputeMtaShare(msg6.Cipherdata)
	if err != nil {
		return errors.New("client ComputeMtaShare(msg6.Cipherdata) error")
	}

	// @client, derive s share
	err = clientEc2fParty.ComputeSShare(x1)
	if err != nil {
		return errors.New("client ComputeSShare() error")
	}

	// check if s shares work
	sClient := clientEc2fParty.Params.SShare.Bytes()
	sProxy := proxyEc2fParty.Params.SShare.Bytes()
	fmt.Println("s share client:", sClient)
	fmt.Println("s share proxy:", sProxy)

	additiveS := new(big.Int).Add(clientEc2fParty.Params.SShare, proxyEc2fParty.Params.SShare)
	fmt.Println("S without mod:", additiveS.Bytes())
	additiveS2 := new(big.Int).Mod(additiveS, curveParams.P)

	fmt.Println("s", additiveS2.Bytes())

	// z_new := make([]byte, len(sClient))
	// for i := 0; i < len(z); i++ {
	// 	z_new[i] = sClient[i] ^ sProxy[i]
	// }
	// fmt.Println("s added:", z_new)

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

func genHePrivateKey(random io.Reader) (*paillier.PrivateKey, error) {

	// generate secret primes
	p, err := rand.Prime(random, 1024)
	if err != nil {
		return nil, errors.New("paillier cryptosystem generates prime number p failed")
	}
	q, err := rand.Prime(random, 1024)
	if err != nil {
		return nil, errors.New("paillier cryptosystem generates prime number q failed")
	}

	// get private key
	return paillier.CreatePrivateKey(p, q), nil
}

// ectf params which are required by all ectf parties

type ec2fParams struct {
	XShare      *big.Int
	YShare      *big.Int
	RhoShare    *big.Int
	MtaShare    *big.Int
	LinearShare *big.Int // in case of delta, this parameter is public
	EtaShare    *big.Int
	SShare      *big.Int

	// extra
	Random     io.Reader
	EcModPrime *big.Int
}

type ec2fParty2 struct {
	Params      *ec2fParams
	HePublicKey *paillier.PublicKey
}

func createEc2fParty2(x2, y2, modP *big.Int, r io.Reader) (*ec2fParty2, error) {

	// init ec2f parameters
	ec2fParams := &ec2fParams{
		XShare:     x2,
		YShare:     y2,
		EcModPrime: modP,
		Random:     r,
	}

	// init party2
	p2 := new(ec2fParty2)

	// compute rhoShare at party 2
	rhoShare, err := genRandom(ec2fParams.Random, modP)
	if err != nil {
		return p2, errors.New("rhoShare genRandom error")
	}
	ec2fParams.RhoShare = rhoShare

	p2.Params = ec2fParams

	return p2, nil
}

func (p2 *ec2fParty2) SetHePublicKey(pubKey []byte) error {
	p2.HePublicKey = new(paillier.PublicKey)
	p2.HePublicKey.N = new(big.Int).SetBytes(pubKey)
	return nil
}

func (p2 *ec2fParty2) MtaEvaluate(cipherData [][]byte, plains ...*big.Int) ([]byte, error) {

	// get public key params
	nSquare := p2.HePublicKey.GetNSquare()

	// compute vector mta
	cipherVector := new(big.Int)
	for i := 0; i < len(cipherData); i++ {

		// parse msg 1 ciphers
		c := new(big.Int).SetBytes(cipherData[i])
		c = new(big.Int).Exp(c, plains[i], nSquare)

		if i > 0 {
			cipherVector = new(big.Int).Mul(cipherVector, c)
		} else {
			cipherVector = c
		}
	}

	// generate random m, -m
	// proxy randness generation for mta sharing (secretMtaBeta)
	mtaRandom, err := genRandom(p2.Params.Random, p2.Params.EcModPrime)
	if err != nil {
		return nil, errors.New("mtaRandom genRandom error")
	}

	// encrypt randomness
	encryptMtaRandom, err := p2.HePublicKey.Encrypt(mtaRandom, p2.Params.Random)
	if err != nil {
		return nil, errors.New("mtaRandom paillier encrypt error")
	}

	// update ciphertext
	cipherVector = new(big.Int).Mul(new(big.Int).Mul(cipherVector, encryptMtaRandom.C), nSquare)

	// -m calculation
	p2.Params.MtaShare = new(big.Int).Mul(new(big.Int).Neg(mtaRandom), nSquare)

	return cipherVector.Bytes(), nil
}

func (p2 *ec2fParty2) ComputeLinearShare(mtaType int) error {
	// linearShare := new(big.Int)
	switch mtaType {
	case 0:
		p2.Params.LinearShare = new(big.Int).Mul(p2.Params.XShare, p2.Params.RhoShare)
	case 1:
		p2.Params.LinearShare = new(big.Int).Mul(p2.Params.YShare, p2.Params.EtaShare)
	}

	p2.Params.LinearShare = new(big.Int).Add(p2.Params.LinearShare, p2.Params.MtaShare)
	p2.Params.LinearShare = new(big.Int).Mod(p2.Params.LinearShare, p2.Params.EcModPrime)
	// p2.Params.LinearShare = linearShare
	return nil
}

func (p2 *ec2fParty2) ComputeEtaShare(externalLinearShare []byte) error {

	// compute sum of linear shares
	parsedLinearShare := new(big.Int).SetBytes(externalLinearShare)
	sumLinearShare := new(big.Int).Add(p2.Params.LinearShare, parsedLinearShare)
	sumLinearShare = new(big.Int).Mod(sumLinearShare, p2.Params.EcModPrime)

	// compute eta at client and compute new mta c1 values
	sumLinearShareInv := new(big.Int).ModInverse(sumLinearShare, p2.Params.EcModPrime)
	p2.Params.EtaShare = new(big.Int).Mod(new(big.Int).Mul(p2.Params.RhoShare, sumLinearShareInv), p2.Params.EcModPrime)

	return nil
}

func (p2 *ec2fParty2) ComputeSShare() error {

	// mtaShare is gamma2
	gamma := p2.Params.MtaShare
	lambda := p2.Params.LinearShare
	x := p2.Params.XShare
	p := p2.Params.EcModPrime

	// compute s share
	two := big.NewInt(2)
	double := new(big.Int).Mul(two, gamma)
	square := new(big.Int).Exp(lambda, two, p)
	p2.Params.SShare = new(big.Int).Add(double, square)
	p2.Params.SShare = new(big.Int).Sub(p2.Params.SShare, x)
	p2.Params.SShare = new(big.Int).Mod(p2.Params.SShare, p)

	// compute linear relation of s share

	return nil
}

type ec2fParty1 struct {
	Params       *ec2fParams
	HePrivateKey *paillier.PrivateKey
}

func createEc2fParty1(x1, y1, modP *big.Int, r io.Reader) (*ec2fParty1, error) {

	// init party1
	p1 := new(ec2fParty1)

	// init ec2f parameters
	ec2fParams := new(ec2fParams)
	ec2fParams.Random = r
	ec2fParams.EcModPrime = modP
	ec2fParams.XShare = new(big.Int).Mod(new(big.Int).Neg(x1), modP)
	ec2fParams.YShare = new(big.Int).Mod(new(big.Int).Neg(y1), modP)
	// ec2fParams := &ec2fParams{
	// 	Random:     r,
	// 	EcModPrime: modP,
	// 	XShare:     new(big.Int).Mod(new(big.Int).Neg(x1), modP),
	// 	YShare:     new(big.Int).Mod(new(big.Int).Neg(y1), modP),
	// }

	// set ec2f params
	p1.Params = ec2fParams

	// rhoShare generation
	rhoShare, err := genRandom(p1.Params.Random, p1.Params.EcModPrime)
	if err != nil {
		return p1, errors.New("rhoShare genRandom error")
	}
	ec2fParams.RhoShare = rhoShare

	// init paillier
	privateKey, err := genHePrivateKey(p1.Params.Random)
	if err != nil {
		return p1, errors.New("genHePrivateKey error")
	}

	// set homomorphic encryption (he) params
	p1.HePrivateKey = privateKey

	return p1, nil
}

func (p1 *ec2fParty1) MtaEncrypt(plains ...*big.Int) ([][]byte, error) {

	// encrypt values
	var cipherdata [][]byte
	for i := 0; i < len(plains); i++ {
		c, err := p1.HePrivateKey.Encrypt(plains[i], p1.Params.Random)
		if err != nil {
			return nil, errors.New("paillier encryption error")
		}
		cipherdata = append(cipherdata, c.C.Bytes())
	}

	return cipherdata, nil
}

func (p1 *ec2fParty1) ComputeMtaShare(cipherdata []byte) error {

	// parse paillier cipher text
	paillierCypher := new(paillier.Cypher)
	paillierCypher.C = new(big.Int).SetBytes(cipherdata)
	p1.Params.MtaShare = p1.HePrivateKey.Decrypt(paillierCypher)
	p1.Params.MtaShare = new(big.Int).Mod(p1.Params.MtaShare, p1.Params.EcModPrime)

	return nil
}

func (p1 *ec2fParty1) ComputeLinearShare(mtaType int) error {

	// compute linearShare
	// linearShare := new(big.Int)
	switch mtaType {
	case 0:
		p1.Params.LinearShare = new(big.Int).Mul(p1.Params.XShare, p1.Params.RhoShare)
	case 1:
		p1.Params.LinearShare = new(big.Int).Mul(p1.Params.YShare, p1.Params.EtaShare)
	}

	p1.Params.LinearShare = new(big.Int).Add(p1.Params.LinearShare, p1.Params.MtaShare)
	p1.Params.LinearShare = new(big.Int).Mod(p1.Params.LinearShare, p1.Params.EcModPrime)

	return nil
}

func (p1 *ec2fParty1) ComputeEtaShare(externalLinearShare []byte) error {

	// compute sum linear share
	parsedLinearShare := new(big.Int).SetBytes(externalLinearShare)
	sumLinearShare := new(big.Int).Add(p1.Params.LinearShare, parsedLinearShare)
	sumLinearShare = new(big.Int).Mod(sumLinearShare, p1.Params.EcModPrime)

	// compute eta at client and compute new mta c1 values
	sumLinearShareInv := new(big.Int).ModInverse(sumLinearShare, p1.Params.EcModPrime)
	p1.Params.EtaShare = new(big.Int).Mod(new(big.Int).Mul(p1.Params.RhoShare, sumLinearShareInv), p1.Params.EcModPrime)

	return nil
}

func (p1 *ec2fParty1) ComputeSShare(x *big.Int) error {

	// mtaShare is gamma1
	gamma := p1.Params.MtaShare
	lambda := p1.Params.LinearShare
	// x := p1.Params.XShare
	p := p1.Params.EcModPrime

	// compute s share
	two := big.NewInt(2)
	double := new(big.Int).Mul(two, gamma)
	square := new(big.Int).Exp(lambda, two, p)
	p1.Params.SShare = new(big.Int).Add(double, square)
	p1.Params.SShare = new(big.Int).Sub(p1.Params.SShare, x)
	p1.Params.SShare = new(big.Int).Mod(p1.Params.SShare, p)

	return nil
}

func (p1 *ec2fParty1) GetHePubKeyBytes() []byte {
	return p1.HePrivateKey.PublicKey.N.Bytes()
}

// messages

type ec2fMtaMsg1 struct {
	Cipherdata  [][]byte
	HePublicKey []byte
}

type ec2fMtaMsg2 struct {
	Cipherdata []byte
	DeltaShare []byte
}

type ec2fMtaMsg3 struct {
	Cipherdata [][]byte
	DeltaShare []byte
}

type ec2fMtaMsg4 struct {
	Cipherdata  []byte
	LambdaShare []byte
}

type ec2fMtaMsg5 struct {
	Cipherdata [][]byte
}

type ec2fMtaMsg6 struct {
	Cipherdata []byte
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

/////////////////////////
// other notation
/////////////////////////

// old sequence in detail

// // p for modulo computations
// modP := curveParams.P

// // pailier parameters
// paillierParams, err := initPaillier(config.rand())
// if err != nil {
// 	return errors.New("initPaillier error")
// }

// // compute rho1 at client
// // curveParams.P, config.rand() // curveParams.P is *big.Int
// rho1, err := genRandom(config.rand(), modP)
// if err != nil {
// 	return errors.New("rho1 genRandom error")
// }

// // turn ec params into big integer numbers
// minusX1 := new(big.Int).Mod(new(big.Int).Neg(x1), modP)
// minusY1 := new(big.Int).Mod(new(big.Int).Neg(y1), modP)

// encryptMinusX1, err := paillierParams.PrivateKey.Encrypt(minusX1, config.rand())
// if err != nil {
// 	return errors.New("paillier encryption minusX1 error")
// }
// encryptRho1, err := paillierParams.PrivateKey.Encrypt(rho1, config.rand())
// if err != nil {
// 	return errors.New("paillier encryption rho1 error")
// }
// access bytes of encrypted paillier value with encryptRho1.C.Bytes()

// sending paillier public key, bytes of encryptRho1, bytes of minusX1

// // proxy paillier public key parsing
// proxyPaillierPubKey := new(paillier.PublicKey)
// proxyPaillierPubKey.N = new(big.Int).SetBytes(paillierParams.PublicKey.N.Bytes())
// nSquare := proxyPaillierPubKey.GetNSquare()

// // compute rho2 at proxy
// rho2, err := genRandom(rand.Reader, modP)
// if err != nil {
// 	return errors.New("rho2 genRandom error")
// }
// // proxy rand m generation, we are calling it secretMtaBeta now
// secretMtaBeta, err := genRandom(rand.Reader, modP)
// if err != nil {
// 	return errors.New("secretMtaBeta genRandom error")
// }

// // parse mta values of client
// parsedEncryptMinusX1 := new(big.Int).SetBytes(encryptMinusX1.C.Bytes())
// parsedEncryptRho1 := new(big.Int).SetBytes(encryptRho1.C.Bytes())

// // vector mta combine encrypted rhos and xX values
// encryptMinusX1Rho2 := new(big.Int).Exp(parsedEncryptMinusX1, rho2, nSquare)
// encryptRho1X2 := new(big.Int).Exp(parsedEncryptRho1, x2, nSquare)
// encryptVec := new(big.Int).Mul(encryptMinusX1Rho2, encryptRho1X2)

// // add encrypted randomness of secretMtaBeta
// // first encrypt secretMtaBeta
// encryptSecretMtaBeta, err := proxyPaillierPubKey.Encrypt(secretMtaBeta, rand.Reader)
// if err != nil {
// 	return errors.New("encryptSecretMtaBeta proxyPaillierPubKey.Encrypt error")
// }
// // now add to encrypted paillier vector of values
// encryptVec = new(big.Int).Mul(encryptVec, encryptSecretMtaBeta.C)
// // vector modulo operation
// encryptVec = new(big.Int).Mul(encryptVec, nSquare)
// // c2Bytes := encryptVec.Bytes()

// // compute proxy alpha2
// proxyAlpha2 := new(big.Int).Neg(secretMtaBeta)
// proxyAlpha2 = new(big.Int).Mod(proxyAlpha2, modP)

// // computing delta2
// delta2 := new(big.Int).Mul(x2, rho2)
// delta2 = new(big.Int).Add(delta2, proxyAlpha2)
// delta2 = new(big.Int).Mod(delta2, modP)

// // share delta2 with client with delta2.Bytes()

// at client

// // decrypt encrypted vector of proxy and access clientAlpha1 value
// // parse paillier cipher text
// paillierCypher := new(paillier.Cypher)
// paillierCypher.C = new(big.Int).SetBytes(encryptVec.Bytes())
// clientAlpha1 := paillierParams.PrivateKey.Decrypt(paillierCypher)
// clientAlpha1 = new(big.Int).Mod(clientAlpha1, modP)

// // compute delta1 at client
// delta1 := new(big.Int).Mul(minusX1, rho1)
// delta1 = new(big.Int).Add(delta1, clientAlpha1)
// delta1 = new(big.Int).Mod(delta1, modP)

// // compute delta at client
// delta2client := new(big.Int).SetBytes(delta2.Bytes())
// clientDelta := new(big.Int).Add(delta1, delta2client)
// clientDelta = new(big.Int).Mod(clientDelta, modP)

// // compute delta at proxy
// delta1proxy := new(big.Int).SetBytes(delta1.Bytes())
// proxyDelta := new(big.Int).Add(delta2, delta1proxy)
// proxyDelta = new(big.Int).Mod(proxyDelta, modP)

// if !bytes.Equal(clientDelta.Bytes(), proxyDelta.Bytes()) {
// 	return errors.New("delta computation failed")
// }

// // compute eta at client and compute new mta c1 values
// deltaInv := new(big.Int).ModInverse(clientDelta, modP)
// eta1 := new(big.Int).Mod(new(big.Int).Mul(rho1, deltaInv), modP)

// // continue to compute ec2f on the client side in 2PC
