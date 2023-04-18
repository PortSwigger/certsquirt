package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/pkg/errors"
	"github.com/sethvargo/go-password/password"
)

// GenerateSubjectKeyID generates Subject Key Identifier (SKI) using SHA-256
// hash of the public key bytes according to RFC 7093 section 2.
func GenerateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(*pub)
		if err != nil {
			return nil, err
		}
	case *ecdsa.PublicKey:
		pubBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	default:
		return nil, errors.New("only ECDSA and RSA public keys are supported")
	}

	hash := sha256.Sum256(pubBytes)

	// According to RFC 7093, The keyIdentifier is composed of the leftmost
	// 160-bits of the SHA-256 hash of the value of the BIT STRING
	// subjectPublicKey (excluding the tag, length, and number of unused bits).
	return hash[:20], nil
}

func loadPemCert(filename string) (crt *x509.Certificate, err error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return crt, err
	}
	block, _ := pem.Decode(bytes)
	return x509.ParseCertificate(block.Bytes)

}

func loadCSR(filename string) (csr *x509.CertificateRequest, err error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return csr, err
	}
	block, _ := pem.Decode(bytes)
	return x509.ParseCertificateRequest(block.Bytes)
}

func loadPubKey(filename string) (key crypto.PublicKey, err error) {
	pemkey, err := os.ReadFile(filename)
	if err != nil {
		return key, err
	}
	block, _ := pem.Decode(pemkey)
	return x509.ParsePKIXPublicKey(block.Bytes)
}

func certToPem(crt []byte, fname string) error {
	block := &pem.Block{
		Type: "CERTIFICATE",
		/*
			// this appears to break openssl.  which says quite a bit about openssl pem parsing...
			Headers: map[string]string{
				  "Issued By": user.Username,
			},
		*/
		Bytes: []byte(crt),
	}
	return os.WriteFile(fname, pem.EncodeToMemory(block), 0644)
}

func newSerialNumber() (*big.Int, error) {
	// ensure we have a decent serial instead of '1' or '42'
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func createIntermediateCert(ctx crypto11.Context, intpubkey crypto.PublicKey, subjectname string) (caName string, ok bool) {
	// need to read in pubkey

	id, err := GenerateSubjectKeyID(intpubkey)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}

	// generate a unique identifier for the CA to go into the Subject name:
	uid, err := password.Generate(6, 2, 0, false, false)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	name := &pkix.Name{}
	name.Country = []string{config.Country}
	name.Organization = []string{config.Organisation}
	name.OrganizationalUnit = []string{config.OrgUnit}
	name.CommonName = config.Organisation + " - Sub CA - " + subjectname + " - " + uid

	serialNumber, err := newSerialNumber()
	if err != nil {
		log.Fatalf("FATAL: Couldn't generate a serial number (%v)", err)
	}

	tmpl := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          serialNumber,
		Subject:               *name,
		NotBefore:             time.Now().Add(time.Second * -600).UTC(),
		NotAfter:              time.Now().AddDate(0, 0, 1825).UTC(),
		SubjectKeyId:          id,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,

		// you may want to undefine this - if you do any end user certs signed by this cert will be scoped
		// to only those usages below.  Of course, this may be what you wish to achieve.
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageOCSPSigning, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		},
		SignatureAlgorithm: x509.SHA512WithRSA,
		// According to Andy C maxpathlen only belongs on the root.
		MaxPathLen: 0,
		// TODO?
		//OCSPServer:         []string{"https://ocsp.security.portswigger.internal"},
	}
	signers, err := ctx.FindAllKeyPairs()
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	// we need the upstream cert
	if _, err := os.Stat(flCaCertFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		log.Fatalf("FATAL: Cannot open the Parent CA Certificate (%v)", err)
	}

	cacert, err := loadPemCert(flCaCertFile)
	log.Printf("INFO: Going to attempt to sign certificate using %v", cacert.Subject.CommonName)
	if err != nil {
		log.Fatalf("FATAL: Cannot read CA Cert from %v (%v)", flCaCertFile, err)
	}

	var signer crypto11.Signer
	if config.UseKms {
		signer = signers[0]
	} else if config.UseYubi {
		signer = signers[1]
	}
	crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, cacert, intpubkey, signer)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	}
	file, err := os.OpenFile(name.CommonName+".pem", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err != nil {
		log.Fatalf("FATAL: trying to write %v.pem file (%v)", name.CommonName, err)
	}
	defer file.Close()
	out := pem.EncodeToMemory(pemBlock)
	if _, err := file.Write(out); err != nil {
		file.Close()
		os.Remove(name.CommonName + ".pem")
		log.Fatalf("FATAL: trying to write %v.pem file (%v)", name.CommonName, err)
	}
	log.Printf("INFO: Successfully wrote out pem cert to %v.pem", name.CommonName)
	// now write out the DER bytes to a crt file
	err = os.WriteFile(name.CommonName+".crt", crtBytes, 0444)
	if err != nil {
		log.Fatalf("FATAL: trying to write %v.crt file (%v)", name.CommonName, err)
	}
	log.Printf("INFO: Successfully wrote out crt file to %v.crt", name.CommonName)
	// now add the cert to the db
	err = addDbRecord(crtBytes)
	if err != nil {
		log.Printf("WARNING: errors occured adding record to db.  Continuing anyway, but please investigate.")
	}
	return name.CommonName, true
}

func signCSR(ctx crypto11.Context, csr *x509.CertificateRequest) (crtBytes []byte, err error) {
	serialNumber, err := newSerialNumber()
	if err != nil {
		log.Fatalf("FATAL: Couldn't generate a serial number (%v)", err)
	}
	id, err := GenerateSubjectKeyID(csr.PublicKey)
	if err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	// overwrite some of the values in the cert.
	var newSubject pkix.Name
	newSubject.Country = append(newSubject.Country, config.Country)
	newSubject.Organization = append(newSubject.Organization, config.Organisation)
	newSubject.Locality = append(newSubject.Locality, config.City)
	newSubject.Province = append(newSubject.Province, config.County)

	// copy *just* this from the original request
	newSubject.CommonName = csr.Subject.CommonName
	// pay no attention to the man on the mountain.
	xx, _ := asn1.Marshal("WC1GYWNlOiAkP2omdGtsMGhydVBmTnJuQVFPQUFnJ2V1YFxkYCZVQT02NFN1WVZTTU9NUFYsfCdNKD9seEV4Rno4cFpRXFFOaHU7YDB9fQogOkw5Qkx5QX1mfi1yVUN+Q1VDcCQtPiVBcUpRa15CJHZUMmoxbkhsO2ByOlgiNjddVXRGVWxqMXElZF1adW42cGteS24kXSwvLSFAPkVpCiAyci0idScoIVVaNndLSSR4cWBLUS55VTRHZCRWIy16el0/V1U0cUcvSDI7J09WJVJcUTJmQjdUMj5eVDtjWTZXbU1FCg==")
	foo := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 13, 37},
		Critical: false,
		Value:    xx,
	}
	yy, _ := asn1.Marshal("aHR0cHM6Ly93d3cuY3MuY211LmVkdS9+cmRyaWxleS80ODcvcGFwZXJzL1Rob21wc29uXzE5ODRfUmVmbGVjdGlvbnNvblRydXN0aW5nVHJ1c3QucGRmCg==")
	bar := pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 13, 38},
		Critical: false,
		Value:    yy,
	}
	tmpl := &x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            newSubject,
		NotBefore:          time.Now().Add(time.Second * -600).UTC(),
		NotAfter:           time.Now().AddDate(0, 0, 365),
		SubjectKeyId:       id,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm: csr.SignatureAlgorithm,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		URIs:               csr.URIs,
	}
	tmpl.ExtraExtensions = []pkix.Extension{bar, foo}

	signers, err := ctx.FindAllKeyPairs()
	if err != nil {
		fmt.Println(err)
		return crtBytes, err
	}
	if flDebug {
		log.Printf("DEBUG: Signers is: %#v", signers)
	}
	// we need the upstream cert
	if _, err := os.Stat(flCaCertFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		log.Fatalf("FATAL: Cannot open the Parent CA Certificate (%v)", err)
	}

	if flDebug {
		log.Printf("DEBUG: attempting to load CA certificate from %v", flCaCertFile)
	}
	cacert, err := loadPemCert(flCaCertFile)
	log.Printf("INFO: Going to attempt to sign certificate using %v", cacert.Subject.CommonName)
	if err != nil {
		log.Fatalf("FATAL: Cannot read CA Cert from %v (%v)", flCaCertFile, err)
	}
	var signer crypto11.Signer
	if config.UseKms {
		signer = signers[0]
	} else if config.UseYubi {
		signer = signers[1]
	}
	if flDebug {
		log.Printf("DEBUG: Signer is %#v", signer)
		log.Printf("DEBUG: Target key (type %T) id is %x", id, signer.Public())
		signerid, err := GenerateSubjectKeyID(signer.Public)
		if err != nil {
			log.Printf("ERROR: Signing public key is whack (%v)", err)
		}
		log.Printf("DEBUG: Signer key is %x", signerid)
	}

	crtBytes, err = x509.CreateCertificate(rand.Reader, tmpl, cacert, csr.PublicKey, signer)
	if err != nil {
		log.Printf("ERROR: is the config file pointing to the correct CA certificate file?")
		log.Fatalf("FATAL: Could not create/sign certificate (%v)", err)
	}
	err = addDbRecord(crtBytes)
	if err != nil {
		log.Printf("WARNING: errors occured adding record to db.  Continuing anyway, but please investigate.")
	}
	log.Printf("INFO: Successfully signed!")
	return crtBytes, err
}

func prettyPrintCSR(csr *x509.CertificateRequest) {
	log.Println("")
	log.Println("******************************************************************")
	log.Println("***         CERTIFICATE SIGNING REQUEST INFORMATION            ***")
	log.Println("******************************************************************")
	log.Println("")
	switch csr.SignatureAlgorithm {
	case x509.SHA256WithRSA:
	case x509.SHA384WithRSA:
	case x509.SHA512WithRSA:
	case x509.ECDSAWithSHA256:
	case x509.ECDSAWithSHA384:
	case x509.ECDSAWithSHA512:
	case x509.SHA256WithRSAPSS:
	case x509.SHA384WithRSAPSS:
	case x509.SHA512WithRSAPSS:
	case x509.PureEd25519:
	default:
		log.Printf("ERROR: Signature type is unsupported (%v) by this CA", csr.SignatureAlgorithm)
		os.Exit(1)
	}
	log.Printf("INFO: Signature algorithm \t%v is acceptable", csr.SignatureAlgorithm)
	log.Printf("INFO: PubKey algorithm is \t%v", csr.PublicKeyAlgorithm)
	log.Printf("INFO: Subject requested is for \t%v", csr.Subject.CommonName)
	log.Printf("INFO: SAN Values to follow:")
	log.Printf("INFO: \t\tDNSNames: %v", csr.DNSNames)
	log.Printf("INFO: \t\tEmailAddresses: %v", csr.EmailAddresses)
	log.Printf("INFO: \t\tIPAddresses: %v", csr.IPAddresses)
	log.Printf("INFO: \t\tURIs: %v", csr.URIs)
}

// This function call should be executed precisely once, to generate the root CA.
// This is effectively creating a 'self-signed' cert.
func createRootCA(ctx crypto11.Context) bool {
	signers, err := ctx.FindAllKeyPairs()
	if err != nil {
		log.Fatalf("%v", err)
	}
	// test we can use to sign and verify
	data := []byte("mary had a little lamb")
	h := sha256.New()
	_, err = h.Write(data)
	if err != nil {
		log.Fatalf("%v", err)
	}
	hash := h.Sum([]byte{})
	var signer crypto11.Signer
	if config.UseKms {
		signer = signers[0]
	} else if config.UseYubi {
		signer = signers[1]
	}
	// on the yubikey, we have to reauth evertime we use the ctx - so skip this part
	if config.UseKms {
		sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
		if err != nil {
			log.Fatalf("%v", err)
		}

		err = rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), crypto.SHA256, hash, sig)
		if err != nil {
			log.Fatalf("%v", err)
		}
		if flDebug {
			log.Printf(("INFO: successfully passed signing test, proceeding"))
		}
	}

	id, err := GenerateSubjectKeyID(signer.Public())
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}
	// this should only ever be used once, well maybe twice.
	// but definately we should have another solution by then.
	name := &pkix.Name{}
	name.Country = []string{config.Country}
	name.Organization = []string{config.Organisation}
	name.OrganizationalUnit = []string{config.OrgUnit}
	name.CommonName = config.CaName + " - " + config.CaVersion

	tmpl := &x509.Certificate{
		IsCA:                  true,
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(31337),
		Subject:               *name,
		NotBefore:             time.Now().Add(time.Second * -600).UTC(),
		NotAfter:              time.Now().AddDate(0, 0, 3650).UTC(),
		SubjectKeyId:          id,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageOCSPSigning,
		},
		SignatureAlgorithm: x509.SHA512WithRSA,
		MaxPathLen:         1,
		// TODO?
		//OCSPServer:         []string{"https://ocsp.security.portswigger.internal"},
	}
	// chomp chomp.
	crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public().(*rsa.PublicKey), signer)
	if err != nil {
		log.Fatalf("FATAL: while trying to sign certificate (%v)", err)
	}
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	}
	file, err := os.OpenFile(name.CommonName+".pem", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err != nil {
		log.Fatalf("FATAL: trying to write %v.pem file (%v)", name.CommonName, err)
	}
	defer file.Close()
	out := pem.EncodeToMemory(pemBlock)
	if _, err := file.Write(out); err != nil {
		file.Close()
		os.Remove(name.CommonName + ".pem")
		log.Fatalf("FATAL: trying to write %v.pem file (%v)", name.CommonName, err)
	}
	log.Printf("INFO: Successfully wrote out pem cert to %v.pem", name.CommonName)
	// now write out the DER bytes to a crt file
	err = os.WriteFile(name.CommonName+".crt", crtBytes, 0444)
	if err != nil {
		log.Fatalf("FATAL: trying to write %v.crt file (%v)", name.CommonName, err)
	}
	log.Printf("INFO: Successfully wrote out crt file to %v.crt", name.CommonName)
	err = addDbRecord(crtBytes)
	if err != nil {
		log.Printf("ERROR: while adding record to DB (non-fatal, but please investigate!)")
	}
	return true
}

// TODO - we should implement a CRL function
func revokeCRT(crt *x509.Certificate) {
	// func CreateRevocationList(rand io.Reader, template *RevocationList, issuer *Certificate, priv crypto.Signer) ([]byte, error)
	// https://pkg.go.dev/crypto/x509#CreateRevocationList
}
