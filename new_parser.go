package tls

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/rs/zerolog/log"
)

type trafficData struct {
	handshakeComplete bool
	vers              int
	filePath          string

	// data buffers
	rawInput bytes.Buffer
	hand     bytes.Buffer
	input    bytes.Buffer

	// cipher
	aead     cipher.AEAD // func(key, fixedNonce []byte) aead
	cipherID uint16
	seq      [8]byte
	cipher   any

	// messages of interest
	clientHello         *clientHelloMsg
	serverHello         *serverHelloMsg
	encryptedExtensions *encryptedExtensionsMsg
	certMsg             *certificateMsgTLS13
	certVerify          *certificateVerifyMsg
	finished            *finishedMsg
}

func newTrafficData(filePath string, version int, cipherID uint16) trafficData {
	return trafficData{
		filePath:          filePath,
		vers:              version,
		handshakeComplete: false,
		cipherID:          cipherID,
	}
}

func (td *trafficData) readTransmissionBitstream() error {

	// open captured raw transcript
	fd, err := os.OpenFile(td.filePath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Error().Err(err).Msg("os.OpenFile")
		return err
	}
	defer fd.Close()

	// file reader to get size
	fileReader := bufio.NewReader(fd)
	fileInfo, err := fd.Stat()
	if err != nil {
		log.Error().Err(err).Msg("fd.Stat()")
		return err
	}
	fileSize := int(fileInfo.Size())

	// read Bitstream
	if err := td.readCompleteBitstream(fileReader, fileSize); err != nil {
		if err == io.ErrUnexpectedEOF && td.rawInput.Len() == 0 {
			err = io.EOF
		}
		return err
	}
	return nil
}

func (td *trafficData) readCompleteBitstream(r io.Reader, fileSize int) error {

	// read raw data into rawInput
	if td.rawInput.Len() == 0 {

		// prepare raw input for required size of file
		td.rawInput.Grow(fileSize)

		// atLeastReader taken from tls Conn.go file
		_, err := td.rawInput.ReadFrom(&atLeastReader{r, int64(fileSize)})
		if err != nil {
			log.Error().Err(err).Msg("td.rawInput.ReadFrom(&atLeastReader{r, int64(fileSize)})")
			return err
		}
		return nil
	}

	return nil
}

func (td *trafficData) parseHello() (interface{}, error) {
	msg, err := td.parseHandshake()
	if err != nil {
		return nil, errors.New("parse Hello error")
	}
	return msg, nil
}

func (td *trafficData) parseHandshake() (interface{}, error) {
	for td.hand.Len() < 4 {
		if err := td.readRecord(); err != nil {
			return nil, err
		}
	}

	data := td.hand.Bytes()
	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshake {
		return nil, errors.New("tls: handshake message of length exceeds maximum  bytes")
	}
	for td.hand.Len() < 4+n {
		if err := td.readRecord(); err != nil {
			return nil, err
		}
	}
	data = td.hand.Next(4 + n)
	var m handshakeMessage
	switch data[0] {
	case typeHelloRequest:
		m = new(helloRequestMsg)
	case typeClientHello:
		m = new(clientHelloMsg)
	case typeServerHello:
		m = new(serverHelloMsg)
	case typeNewSessionTicket:
		m = new(newSessionTicketMsgTLS13)
	case typeCertificate:
		m = new(certificateMsgTLS13)
	case typeCertificateRequest:
		m = new(certificateRequestMsgTLS13)
	case typeCertificateStatus:
		m = new(certificateStatusMsg)
	case typeServerKeyExchange:
		m = new(serverKeyExchangeMsg)
	case typeServerHelloDone:
		m = new(serverHelloDoneMsg)
	case typeClientKeyExchange:
		m = new(clientKeyExchangeMsg)
	case typeCertificateVerify:
		m = &certificateVerifyMsg{
			hasSignatureAlgorithm: td.vers >= VersionTLS12,
		}
	case typeFinished:
		m = new(finishedMsg)
	case typeEncryptedExtensions:
		m = new(encryptedExtensionsMsg)
	case typeEndOfEarlyData:
		m = new(endOfEarlyDataMsg)
	case typeKeyUpdate:
		m = new(keyUpdateMsg)
	default:
		return nil, errors.New("tls parser: unexpected handshake type")
	}

	// The handshake message unmarshalers
	// expect to be able to keep references to data,
	// so pass in a fresh copy that won't be overwritten.
	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, errors.New("tls parser: unmarshal error")
	}
	return m, nil
}

func (td *trafficData) readRecord() error {

	if td.rawInput.Len() <= 0 {
		log.Debug().Msg("done transcript parsing")
		return nil
	}
	handshakeComplete := td.handshakeComplete

	td.input.Reset()

	hdr := td.rawInput.Bytes()[:recordHeaderLen]
	typ := recordType(hdr[0])

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if !handshakeComplete && typ == 0x80 {
		log.Error().Msg("tls parser: unsupported SSLv2 handshake received\n")
		return alertProtocolVersion
	}

	//vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	n := int(hdr[3])<<8 | int(hdr[4])

	if n > maxCiphertextTLS13 {
		log.Error().Msg("tls parser: oversized record received with length")
		return alertRecordOverflow
	}

	record := td.rawInput.Next(recordHeaderLen + n)
	data, typ, err := td.decrypt(record)
	if err != nil {
		return err
	}
	if len(data) > maxPlaintext {
		return alertRecordOverflow
	}

	switch typ {
	default:
		return alertUnexpectedMessage
	case recordTypeAlert:
		return alertUnexpectedMessage
	case recordTypeChangeCipherSpec:
		td.handshakeComplete = true
		return td.readRecord()
	case recordTypeApplicationData:

		if len(data) == 0 {
			return td.readRecord()
		}
		// Note that data is owned by p.rawInput, following the Next call above,
		// to avoid copying the plaintext. This is safe because p.rawInput is
		// not read from or written to until p.input is drained.
		td.input.Reset()

	case recordTypeHandshake:
		td.hand.Write(data)
	}
	return nil
}

func (td *trafficData) decrypt(record []byte) ([]byte, recordType, error) {
	var plaintext []byte
	typ := recordType(record[0])
	payload := record[recordHeaderLen:]

	// In TLS 1.3, change_cipher_spec messages are to be ignored without being
	// decrypted. See RFC 8446, Appendix D.4.
	if td.vers == VersionTLS13 && typ == recordTypeChangeCipherSpec {
		return payload, typ, nil
	}

	explicitNonceLen := 0

	if td.cipher != nil && td.handshakeComplete {

		// not called when parsing hello messages
		// decryption parameters must be set before parsing tls1.3 messages not of type hello

		if len(payload) < explicitNonceLen {
			return nil, 0, alertBadRecordMAC
		}
		nonce := payload[:explicitNonceLen]
		if len(nonce) == 0 {
			nonce = td.seq[:]
		}
		payload = payload[explicitNonceLen:]

		var additionalData []byte

		additionalData = record[:recordHeaderLen]

		var err error
		// c := td.cipher.(aead)
		aead := td.aead
		plaintext, err = aead.Open(payload[:0], nonce, payload, additionalData)
		if err != nil {
			return nil, 0, alertBadRecordMAC
		}

		if td.vers == VersionTLS13 {
			if typ != recordTypeApplicationData {
				return nil, 0, alertUnexpectedMessage
			}
			if len(plaintext) > maxPlaintext+1 {
				return nil, 0, alertRecordOverflow
			}
			// Remove padding and find the ContentType scanning from the end.
			for i := len(plaintext) - 1; i >= 0; i-- {
				if plaintext[i] != 0 {
					typ = recordType(plaintext[i])
					plaintext = plaintext[:i]
					break
				}
				if i == 0 {
					return nil, 0, alertUnexpectedMessage
				}
			}
		}
	} else {
		plaintext = payload
	}

	td.incSeq()
	return plaintext, typ, nil
}

func (td *trafficData) incSeq() {
	for i := 7; i >= 0; i-- {
		td.seq[i]++
		if td.seq[i] != 0 {
			return
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("sequence number wraparound")
}

func (td *trafficData) setCipherParameters(secret []byte) error {
	cipher := cipherSuiteTLS13ByID(td.cipherID)
	key, iv := cipher.trafficKey(secret)
	td.aead = cipher.aead(key, iv)
	td.cipher = cipher
	for i := range td.seq {
		td.seq[i] = 0
	}
	return nil
}

func (td *trafficData) parseServerEncryptedExtension() (interface{}, error) {
	msg, err := td.parseHandshake()
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (td *trafficData) parseServerCertificate() (interface{}, error) {
	msg, err := td.parseHandshake()

	certReq, ok := msg.(*certificateRequestMsgTLS13)
	if ok {
		p.transcript.Write(certReq.marshal())
		msg, err = td.parseHandshake()
		if err != nil {
			return nil, err
		}
	}

	certMsg, ok := msg.(*certificateMsgTLS13)
	td.certMsg = certMsg
	if !ok {
		return nil, unexpectedMessageError(certMsg, msg)
	}
	p.transcript.Write(certMsg.marshal())
	if len(certMsg.certificate.Certificate) == 0 {
		return nil, errors.New("tls: received empty certificates message")
	}

	if err := p.verifyServerCertificate(certMsg.certificate.Certificate); err != nil {
		return nil, err
	}

	msg, err = p.parseHandshake()
	if err != nil {
		return nil, err
	}

	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		return nil, unexpectedMessageError(certVerify, msg)
	}

	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms) {
		return nil, errors.New("tls: certificate used with invalid signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return nil, err
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		return nil, errors.New("tls: certificate used with invalid signature algorithm")
	}

	signed := signedMessage(sigHash, serverSignatureContext, p.transcript)
	if err := verifyHandshakeSignature(sigType, p.peerCertificates[0].PublicKey,
		sigHash, signed, certVerify.signature); err != nil {
		return nil, errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}
	p.transcript.Write(certVerify.marshal())
	return certVerify, nil
}

func (td *trafficData) parseFinishedMsg() (interface{}, error) {
	msg, err := td.parseHandshake()
	if err != nil {
		return nil, err
	}
	finished, ok := msg.(*finishedMsg)
	if !ok {
		return nil, unexpectedMessageError(finished, msg)
	}
	return msg, nil
}

type handshakeSecrets struct {
	shts                   []byte
	nonce                  []byte
	additionalData         []byte
	intermediateHashHSipad []byte
	intermediateHashHSopad []byte
}

func NewHandshakeSecrets(filePath string) (handshakeSecrets, error) {

	// init new struct
	hss := handshakeSecrets{}

	// open file
	file, err := os.Open("./request/session.json")
	if err != nil {
		log.Error().Err(err).Msg("os.Open")
		return hss, err
	}
	defer file.Close()

	// read in data
	data, err := ioutil.ReadAll(file)
	if err != nil {
		log.Error().Err(err).Msg("ioutil.ReadAll(file)")
		return hss, err
	}

	// parse json
	var objmap map[string]string
	err = json.Unmarshal(data, &objmap)
	if err != nil {
		log.Error().Err(err).Msg("json.Unmarshal(data, &objmap)")
		return hss, err
	}

	// convert values to byte slices
	hss.shts, _ = hex.DecodeString(objmap["SHTS"])
	hss.nonce, _ = hex.DecodeString(objmap["nonce"])
	hss.additionalData, _ = hex.DecodeString(objmap["additionalData"])
	hss.intermediateHashHSipad, _ = hex.DecodeString(objmap["intermediateHashHSipad"])
	hss.intermediateHashHSopad, _ = hex.DecodeString(objmap["intermediateHashHSopad"])

	// take out values of interest
	return hss, nil
}

type Parser struct {

	// tls cipher suite data
	cipherID uint16
	vers     int
	// transcript hash.Hash
	h2 string

	// secret data
	hsSecrets handshakeSecrets

	// raw data
	tdClient trafficData
	tdServer trafficData

	// certificates
	certPool         *x509.CertPool
	verifiedChains   [][]*x509.Certificate
	peerCertificates []*x509.Certificate

	// file handling
	clientFilePath   string
	serverFilePath   string
	storagePath      string
	secretPath       string
	caPath           string
	serverRecordPath string
	clientRecordPath string
}

func NewParser() (*Parser, error) {
	parser := new(Parser)

	// config parameters
	parser.storagePath = "./local_storage/"
	parser.serverRecordPath = "ServerSentRecords.raw"
	parser.clientRecordPath = "ClientSentRecords.raw"
	parser.caPath = "../certs/certificates/ca.crt"
	parser.clientFilePath = parser.storagePath + parser.clientRecordPath
	parser.serverFilePath = parser.storagePath + parser.serverRecordPath
	parser.secretPath = "../client/postprocess/kdc_public.json"

	// configure tls 1.3 parameters
	// parser.handshakeComplete = false
	parser.vers = VersionTLS13
	parser.cipherID = TLS_AES_128_GCM_SHA256
	// cipher := cipherSuiteTLS13ByID(parser.cipherID)
	// parser.transcript = cipher.hash.New()

	// get server certificate file
	caCert, err := ioutil.ReadFile(parser.caPath)
	if err != nil {
		log.Error().Err(err).Msg("ioutil.ReadFile(parser.CaPath)")
		return nil, err
	}
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		log.Error().Err(err).Msg("x509.SystemCertPool()")
		return nil, err
	}
	caCertPool.AppendCertsFromPEM(caCert)
	parser.certPool = caCertPool

	return parser, nil
}

// reads in client secret parameters to decrypt handshake traffic
func (p *Parser) ReadSecrets() error {
	hss, err := NewHandshakeSecrets(p.secretPath)
	if err != nil {
		log.Error().Err(err).Msg("hss.setHandshakeSecrets(p.secretPath)")
		return err
	}
	p.hsSecrets = hss
	return nil
}

// read transcript reads raw tls traffic
// sets all tls messages
func (p *Parser) ReadTranscript() error {

	// sets client rawInput data
	p.tdClient = newTrafficData(p.clientFilePath, p.vers, p.cipherID)
	err := p.tdClient.readTransmissionBitstream()
	if err != nil {
		log.Error().Err(err).Msg("p.tdClient.readTransmissionBitstream()")
		return err
	}

	// set server rawInput data
	p.tdServer = newTrafficData(p.serverFilePath, p.vers, p.cipherID)
	err = p.tdServer.readTransmissionBitstream()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.readTransmissionBitstream()")
		return err
	}

	// set client hello
	msg, err := p.tdClient.parseHello()
	if err != nil {
		log.Error().Err(err).Msg("p.tdClient.parseHello()")
		return err
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		return errors.New("cannot typecast clientHello")
	}
	p.tdClient.clientHello = clientHello

	// set server hello
	msg, err = p.tdServer.parseHello()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.parseHello()")
		return err
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		return errors.New("cannot typecast serverHello")
	}
	p.tdServer.serverHello = serverHello

	// capture H2
	h2, err := p.GetH2()
	if err != nil {
		log.Error().Err(err).Msg("p.GetH2()")
		return err
	}
	p.h2 = hex.EncodeToString(h2)

	fmt.Println("done parsing client and server hello msg")

	// derive encryption keys from SHTS
	p.tdServer.setCipherParameters(p.hsSecrets.shts)

	// continue parsing server encrypted extension
	msg, err = p.tdServer.parseServerEncryptedExtension()
	if err != nil {
		log.Error().Err(err).Msg("p.tdServer.parseServerEncryptedExtension()")
		return err
	}
	encryptedExtensions, ok := msg.(*encryptedExtensionsMsg)
	if !ok {
		return errors.New("cannot typecast encryptedExtensionsMsg")
	}
	p.tdServer.encryptedExtensions = encryptedExtensions

	// parse server certificate
	msg, err = serverSentRecordsParser.parseServerCertificate()
	if err != nil {
		log.Error().Err(err).Msg("encryptedExtensions.marshal()")
		return err
	}
	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		return errors.New("cannot typecast certificateVerifyMsg")
	}
	serverSentRecordsParser.certVerify = certVerify
	// fmt.Printf("TLS Parser: decrypted cert verify message: %x\n", certVerify.raw)

	msg, err = p.tdServer.parseFinishedMsg()
	finished, ok := msg.(*finishedMsg)
	if !ok {
		return errors.New("cannot typecast finishedMsg")
	}
	serverSentRecordsParser.finished = finished

	return nil
}

// func (td *trafficData) resetSeq() {
// 	for i := range td.seq {
// 		td.seq[i] = 0
// 	}
// }

// func (p *Parser) readNextRecordWithoutDecryption() error {
// 	if p.rawInput.Len() <= 0 {
// 		log.Println("no record")
// 		return nil
// 	}
// 	handshakeComplete := p.handshakeComplete

// 	p.input.Reset(nil)

// 	hdr := p.rawInput.Bytes()[:recordHeaderLen]
// 	typ := recordType(hdr[0])

// 	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
// 	// start with a uint16 length where the MSB is set and the first record
// 	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
// 	// an SSLv2 client.
// 	if !handshakeComplete && typ == 0x80 {
// 		log.Fatalf("tls parser: unsupported SSLv2 handshake received\n")
// 		return alertProtocolVersion
// 	}

// 	//vers := uint16(hdr[1])<<8 | uint16(hdr[2])
// 	n := int(hdr[3])<<8 | int(hdr[4])

// 	if n > maxCiphertextTLS13 {
// 		log.Fatalf("tls parser: oversized record received with length %d", n)
// 		return alertRecordOverflow
// 	}

// 	record := p.rawInput.Next(recordHeaderLen + n)
// 	p.input.Reset(record)
// 	return nil
// }

func (p *Parser) parseApplicationData() error {
	if err := p.readRecord(); err != nil {
		return err
	}
	return nil
}

// func (p *Parser) VerifyGCMTag(seq int, startBlockIdx, endBlockIdx int, tagMaskCipher, galoisKexCipher []byte) (bool, []byte) {

// 	//policyExtractByte, _ := ioutil.ReadAll(policyExtractFile)
// 	//var pe policyExtract
// 	//json.Unmarshal(policyExtractByte, &pe)
// 	//seq, _ := strconv.ParseUint(pe.Seq, 16, 32)
// 	var i int
// 	for i = 0; i <= seq; i++ {
// 		if p.rawInput.Len() <= 0 {
// 			break
// 		}
// 		p.readNextRecordWithoutDecryption()
// 		tmp := make([]byte, 2048)
// 		n, _ := p.input.Read(tmp)

// 		if seq == i {
// 			tag := DynAuthGCM(tagMaskCipher, tmp[5:n-16], galoisKexCipher, tmp[0:5])
// 			if bytes.Compare(tag, tmp[n-16:n]) != 0 {
// 				fmt.Println("Tag calculation failed.")
// 			}
// 			// fmt.Println("tag authen success")

// 			return true, tmp[:n][startBlockIdx*16+5 : endBlockIdx*16+5]
// 		}

// 	}
// 	// fmt.Println("end")
// 	return false, nil
// }

func (p *Parser) verifyServerCertificate(certificates [][]byte) error {
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}
	opts := x509.VerifyOptions{
		Roots:         p.certPool,
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	var err error
	p.verifiedChains, err = certs[0].Verify(opts)
	if err != nil {
		return err
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	p.peerCertificates = certs

	return nil
}

func (p *Parser) GetH0() []byte {

	// compute transcript hash
	cipher := cipherSuiteTLS13ByID(p.cipherID)
	transcript := cipher.hash.New()
	return transcript.Sum(nil)
}

func (p *Parser) GetH2() ([]byte, error) {

	// deserialize transcripts
	chTranscript, err := p.tdClient.clientHello.marshal()
	if err != nil {
		log.Error().Err(err).Msg("clientHello.marshal()")
		return nil, err
	}
	shTranscript, err := p.tdServer.serverHello.marshal()
	if err != nil {
		log.Error().Err(err).Msg("serverHello.marshal()")
		return nil, err
	}

	// compute transcript hash
	cipher := cipherSuiteTLS13ByID(p.cipherID)
	transcript := cipher.hash.New()
	transcript.Write(chTranscript)
	transcript.Write(shTranscript)
	return transcript.Sum(nil), nil
}

func (p *Parser) GetH3() []byte {

	// deserialize transcripts
	chTranscript, err := p.tdClient.clientHello.marshal()
	if err != nil {
		log.Error().Err(err).Msg("clientHello.marshal()")
		return nil, err
	}
	shTranscript, err := p.tdServer.serverHello.marshal()
	if err != nil {
		log.Error().Err(err).Msg("serverHello.marshal()")
		return nil, err
	}
	eeTranscript, err := p.tdServer.encryptedExtensions.marshal()
	if err != nil {
		log.Error().Err(err).Msg("encryptedExtensions.marshal()")
		return err
	}

	// compute transcript hash

	cipher := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	transcript := cipher.hash.New()
	transcript.Write(p.clientHello.marshal())
	transcript.Write(p.serverHello.marshal())
	transcript.Write(p.encryptedExtensions.marshal())
	transcript.Write(p.certMsg.marshal())
	transcript.Write(p.certVerify.marshal())
	transcript.Write(p.finished.marshal())
	return transcript.Sum(nil)
}

func (p *Parser) GetH7() []byte {
	cipher := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	transcript := cipher.hash.New()
	transcript.Write(p.clientHello.marshal())
	transcript.Write(p.serverHello.marshal())
	transcript.Write(p.encryptedExtensions.marshal())
	transcript.Write(p.certMsg.marshal())
	transcript.Write(p.certVerify.marshal())
	return transcript.Sum(nil)
}
func (*Parser) GetL3() string {
	return "derived"
}

func (*Parser) GetL5() string {
	return serverHandshakeTrafficLabel
}

func (*Parser) GetL6() string {
	return "finished"
}
func (*Parser) GetL7() string {
	return clientApplicationTrafficLabel
}
func (*Parser) GetL8() string {
	return serverApplicationTrafficLabel
}

func (p *Parser) GetSF() []byte {
	return p.finished.verifyData
}
