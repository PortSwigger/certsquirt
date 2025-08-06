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
	"math/big"
	"os"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/pkg/errors"
	"github.com/sethvargo/go-password/password"
)

// TODO - we should implement a CRL function
func revokeCRT(crt *x509.Certificate) {
	// func CreateRevocationList(rand io.Reader, template *RevocationList, issuer *Certificate, priv crypto.Signer) ([]byte, error)
	// https://pkg.go.dev/crypto/x509#CreateRevocationList
}

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

// This function call should be executed precisely once, to generate the root CA.
// This is effectively creating a 'self-signed' cert.
func createRootCA(signer crypto11.Signer) bool {
	logger := GetLogger()
	id, err := GenerateSubjectKeyID(signer.Public())
	if err != nil {
		logger.Error("Cannot generate subject key ID for root CA", "error", err)
		return false
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
		// according to https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.8.7.pdf
		// we shouldn't set this. See 7.1.2.1.b Root CA Certificate for details
		//ExtKeyUsage: []x509.ExtKeyUsage{
		//	x509.ExtKeyUsageOCSPSigning,
		//},
		SignatureAlgorithm: x509.SHA512WithRSA,
		// as above, should not be set 7.1.2.1.a for details
		//MaxPathLen: 1,
		// TODO?
		//OCSPServer:         []string{"https://ocsp.security.portswigger.internal"},
	}
	if config.CaAiaRootURL != "" {
		tmpl.IssuingCertificateURL = append(tmpl.IssuingCertificateURL, config.CaAiaRootURL)
	}
	if config.OCSPServer != "" {
		tmpl.OCSPServer = append(tmpl.OCSPServer, config.OCSPServer)
	}
	// chomp chomp.
	crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public().(*rsa.PublicKey), signer)
	if err != nil {
		logger.Error("Certificate signing failed for root CA", "error", err, "subject", name.CommonName)
		return false
	}
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	}
	file, err := os.OpenFile(name.CommonName+".pem", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		logger.Error("Cannot create PEM certificate file", 
			"error", err, 
			"filename", name.CommonName+".pem",
			"subject", name.CommonName)
		return false
	}
	defer file.Close()
	out := pem.EncodeToMemory(pemBlock)
	if _, err := file.Write(out); err != nil {
		file.Close()
		os.Remove(name.CommonName + ".pem")
		logger.Error("Cannot write PEM certificate file", 
			"error", err, 
			"filename", name.CommonName+".pem",
			"subject", name.CommonName)
		return false
	}
	logger.Info("Successfully wrote PEM certificate file", 
		"filename", name.CommonName+".pem",
		"subject", name.CommonName)
	// now write out the DER bytes to a crt file
	err = os.WriteFile(name.CommonName+".crt", crtBytes, 0644)
	if err != nil {
		logger.Error("Cannot write CRT certificate file", 
			"error", err, 
			"filename", name.CommonName+".crt",
			"subject", name.CommonName)
		return false
	}
	logger.Info("Successfully wrote CRT certificate file", 
		"filename", name.CommonName+".crt",
		"subject", name.CommonName)
	err = addDbRecord(crtBytes)
	if err != nil {
		logger.Warn("Failed to add certificate to database - please investigate", 
			"error", err,
			"subject", name.CommonName)
	}
	
	AuditEvent("root_ca_creation", true,
		"subject", name.CommonName,
		"serial", tmpl.SerialNumber.String(),
		"not_after", tmpl.NotAfter,
		"pem_file", name.CommonName+".pem",
		"crt_file", name.CommonName+".crt")
		
	return true
}

func createIntermediateCert(signer crypto11.Signer, intpubkey crypto.PublicKey, subjectname string) (caName string, ok bool) {
	logger := GetLogger()
	// need to read in pubkey
	id, err := GenerateSubjectKeyID(intpubkey)
	if err != nil {
		logger.Error("Cannot generate subject key ID for intermediate CA", "error", err)
		return "", false
	}

	// generate a unique identifier for the CA to go into the Subject name:
	uid, err := password.Generate(6, 2, 0, false, false)
	if err != nil {
		logger.Error("Cannot generate unique identifier for intermediate CA", "error", err)
		return "", false
	}
	name := &pkix.Name{}
	name.Country = []string{config.Country}
	name.Organization = []string{config.Organisation}
	name.OrganizationalUnit = []string{config.OrgUnit}
	name.CommonName = config.Organisation + " - Sub CA - " + subjectname + " - " + uid

	serialNumber, err := newSerialNumber()
	if err != nil {
		logger.Error("Cannot generate serial number for intermediate CA", "error", err)
		return "", false
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
		// More details here: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-1.8.7.pdf
		// See section 7.1.2.2 Subordinate CA Certificate item g.
		//ExtKeyUsage: []x509.ExtKeyUsage{
		//	x509.ExtKeyUsageOCSPSigning, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth,
		//},
		SignatureAlgorithm: x509.SHA512WithRSA,
		// define this here.
		MaxPathLen: 0,
		// TODO?
		//OCSPServer:         []string{"https://ocsp.security.portswigger.internal"},
	}
	if config.CaAiaRootURL != "" {
		tmpl.IssuingCertificateURL = append(tmpl.IssuingCertificateURL, config.CaAiaRootURL)
	}
	if config.OCSPServer != "" {
		tmpl.OCSPServer = append(tmpl.OCSPServer, config.OCSPServer)
	}
	// we need the upstream cert
	if _, err := os.Stat(flCaCertFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		logger.Error("Parent CA certificate file not found", 
			"error", err, 
			"ca_cert_file", flCaCertFile)
		return "", false
	}

	cacert, err := loadPemCert(flCaCertFile)
	if err != nil {
		logger.Error("Cannot read parent CA certificate", 
			"error", err, 
			"ca_cert_file", flCaCertFile)
		return "", false
	}
	
	logger.Info("Signing intermediate certificate", 
		"signing_ca", cacert.Subject.CommonName,
		"intermediate_subject", name.CommonName)

	crtBytes, err := x509.CreateCertificate(rand.Reader, tmpl, cacert, intpubkey, signer)
	if err != nil {
		logger.Error("Certificate signing failed for intermediate CA", 
			"error", err,
			"intermediate_subject", name.CommonName,
			"signing_ca", cacert.Subject.CommonName)
		return "", false
	}
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtBytes,
	}
	file, err := os.OpenFile(name.CommonName+".pem", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		logger.Error("Cannot create PEM certificate file for intermediate CA", 
			"error", err, 
			"filename", name.CommonName+".pem",
			"subject", name.CommonName)
		return "", false
	}
	defer file.Close()
	out := pem.EncodeToMemory(pemBlock)
	if _, err := file.Write(out); err != nil {
		file.Close()
		os.Remove(name.CommonName + ".pem")
		logger.Error("Cannot write PEM certificate file for intermediate CA", 
			"error", err, 
			"filename", name.CommonName+".pem",
			"subject", name.CommonName)
		return "", false
	}
	logger.Info("Successfully wrote PEM certificate file for intermediate CA", 
		"filename", name.CommonName+".pem",
		"subject", name.CommonName)
	// now write out the DER bytes to a crt file
	err = os.WriteFile(name.CommonName+".crt", crtBytes, 0644)
	if err != nil {
		logger.Error("Cannot write CRT certificate file for intermediate CA", 
			"error", err, 
			"filename", name.CommonName+".crt",
			"subject", name.CommonName)
		return "", false
	}
	logger.Info("Successfully wrote CRT certificate file for intermediate CA", 
		"filename", name.CommonName+".crt",
		"subject", name.CommonName)
	// now add the cert to the db
	err = addDbRecord(crtBytes)
	if err != nil {
		logger.Warn("Failed to add intermediate certificate to database", 
			"error", err,
			"subject", name.CommonName)
	}
	
	AuditEvent("intermediate_ca_creation", true,
		"subject", name.CommonName,
		"signing_ca", cacert.Subject.CommonName,
		"serial", serialNumber.String(),
		"not_after", tmpl.NotAfter,
		"pem_file", name.CommonName+".pem",
		"crt_file", name.CommonName+".crt")
		
	return name.CommonName, true
}

func signCSR(signer crypto11.Signer, csr *x509.CertificateRequest) (crtBytes []byte, err error) {
	logger := GetLogger()
	serialNumber, err := newSerialNumber()
	if err != nil {
		logger.Error("Cannot generate serial number for CSR certificate", "error", err)
		return nil, err
	}
	id, err := GenerateSubjectKeyID(csr.PublicKey)
	if err != nil {
		logger.Error("Cannot generate subject key ID for CSR certificate", "error", err)
		return nil, err
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
		NotAfter:           time.Now().AddDate(0, 0, flTtl),
		SubjectKeyId:       id,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		SignatureAlgorithm: csr.SignatureAlgorithm,
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		URIs:               csr.URIs,
	}
	if flOcspSigner {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning)
	}
	tmpl.ExtraExtensions = []pkix.Extension{bar, foo}
	// if config.CaAiaIssuerURL != "" {
	// 	tmpl.IssuingCertificateURL = append(tmpl.IssuingCertificateURL, config.CaAiaIssuerURL)
	// }
	if config.CaAiaRootURL != "" {
		tmpl.IssuingCertificateURL = append(tmpl.IssuingCertificateURL, config.CaAiaRootURL)
	}
	if config.OCSPServer != "" {
		tmpl.OCSPServer = append(tmpl.OCSPServer, config.OCSPServer)
	}

	// we need the upstream cert
	if _, err := os.Stat(flCaCertFile); os.IsNotExist(err) {
		// path/to/whatever does not exist
		logger.Error("Parent CA certificate file not found for CSR signing", 
			"error", err, 
			"ca_cert_file", flCaCertFile)
		return nil, err
	}

	if flDebug {
		logger.Debug("Loading CA certificate for CSR signing", "ca_cert_file", flCaCertFile)
	}
	cacert, err := loadPemCert(flCaCertFile)
	if err != nil {
		logger.Error("Cannot read CA certificate for CSR signing", 
			"error", err, 
			"ca_cert_file", flCaCertFile)
		return nil, err
	}
	
	logger.Info("Signing certificate request", 
		"signing_ca", cacert.Subject.CommonName,
		"csr_subject", csr.Subject.CommonName)

	if flDebug {
		logger.Debug("Certificate signing details",
			"signer_type", fmt.Sprintf("%T", signer),
			"target_key_type", fmt.Sprintf("%T", csr.PublicKey),
			"target_key_id", fmt.Sprintf("%x", id))
		signerid, err := GenerateSubjectKeyID(signer.Public())
		if err != nil {
			logger.Error("Cannot generate subject key ID for signing key", "error", err)
		} else {
			logger.Debug("Signing key details", "signer_key_id", fmt.Sprintf("%x", signerid))
		}
	}

	crtBytes, err = x509.CreateCertificate(rand.Reader, tmpl, cacert, csr.PublicKey, signer)
	if err != nil {
		logger.Error("Certificate creation/signing failed", 
			"error", err,
			"csr_subject", csr.Subject.CommonName,
			"ca_subject", cacert.Subject.CommonName,
			"suggestion", "verify config file points to correct CA certificate")
		return nil, err
	}
	
	// Add certificate to database
	err = addDbRecord(crtBytes)
	if err != nil {
		logger.Warn("Failed to add certificate to database", 
			"error", err,
			"csr_subject", csr.Subject.CommonName)
		// Continue anyway, don't fail the signing operation
	}
	
	logger.Info("Certificate signing completed successfully", 
		"csr_subject", csr.Subject.CommonName,
		"ca_subject", cacert.Subject.CommonName,
		"serial", serialNumber.String())
		
	AuditEvent("certificate_signed", true,
		"csr_subject", csr.Subject.CommonName,
		"ca_subject", cacert.Subject.CommonName,
		"serial", serialNumber.String(),
		"not_after", tmpl.NotAfter)
		
	return crtBytes, nil
}

func prettyPrintCSR(csr *x509.CertificateRequest) {
	logger := GetLogger()
	logger.Info("******************************************************************")
	logger.Info("***         CERTIFICATE SIGNING REQUEST INFORMATION            ***") 
	logger.Info("******************************************************************")
	
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
		logger.Error("Signature algorithm not supported by this CA", 
			"algorithm", csr.SignatureAlgorithm,
			"subject", csr.Subject.CommonName)
		os.Exit(1)
	}
	
	logger.Info("Certificate signing request details",
		"signature_algorithm", csr.SignatureAlgorithm.String(),
		"public_key_algorithm", csr.PublicKeyAlgorithm.String(), 
		"subject", csr.Subject.CommonName,
		"dns_names", csr.DNSNames,
		"email_addresses", csr.EmailAddresses,
		"ip_addresses", csr.IPAddresses,
		"uris", csr.URIs)
}
