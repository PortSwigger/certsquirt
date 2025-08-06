package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	_ "embed"

	"github.com/sethvargo/go-password/password"
)

type Config struct {
	Organisation string `json:""`
	Country      string `json:""`
	CaName       string `json:""`
	CaVersion    string `json:""`
	//CaAiaIssuerURL string `json:""`
	CaAiaRootURL   string `json:""`
	OrgUnit        string `json:""`
	City           string `json:""`
	County         string `json:""`
	OCSPServer     string `json:""`
	AwsRoleARN     string `json:""`
	AwsMfaSerial   string `json:""`
	AwsDbTableName string `json:""`
	AwsAccessKey   string `json:""`
	AwsSecretKey   string `json:""`
	AwsTotpSecret  string `json:""`
	AwsRegion      string `json:""`
	Path           string `json:"P11Path"`
	TokenLabel     string `json:"P11TokenLabel"`
	Pin            string `json:"P11Pin"`
	SlotNumber     int    `json:"P11Slot"`
	SigningCert    string `json:""`
	// Logging configuration
	LogLevel       string `json:"LogLevel,omitempty"`       // DEBUG, INFO, WARN, ERROR
	LogFormat      string `json:"LogFormat,omitempty"`      // json or text
	AuditLogFile   string `json:"AuditLogFile,omitempty"`   // path to audit log file
}

var config Config

// command line flags/arguments
var flShowVersion, flCA, flSign, flSubCa, flBootstrap, flUsage, flDebug, flGenPrivKey, flOcspSigner bool
var flCSR, flPubKey, flCaCertFile, flInterName, flConfig string
var flTtl int

var keypassword string
var buildstamp, githash string // For versioning, via go build -v -x -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" || exit'`

//go:embed VERSION
var version string

func main() {
	var err error
	// Root CA Based operations
	flag.BoolVar(&flCA, "ca", false, "create a ca.  also requires -bootstrap to confirm.")
	flag.BoolVar(&flBootstrap, "bootstrap", false, "required to confirm you really want to bootstrap the ca.  you almost certainly don't want to do this.")

	// CSR Based operations
	flag.StringVar(&flCSR, "csr", "", "read from filename and sign/inspect a csr from another system.")
	flag.BoolVar(&flSign, "sign", false, "actually issue a certificate from a csr.")
	flag.BoolVar(&flOcspSigner, "ocspsigner", false, "*dangerous* - indicate this certificate can be used for OCSP signing. Be sure you need this!")

	// Intermediate based operations
	flag.BoolVar(&flSubCa, "subca", false, "indicates you want to sign another CA's CSR (ca:true) to authorize it's operation as a sub CA.  Use with 'bootstrap' flag to create one automatically.")
	flag.StringVar(&flInterName, "subcaname", "", "extend the SubjectName, to identify an intermediate certificate (e.g. Fortinet Edge FW-A)")
	flag.StringVar(&flPubKey, "pubkey", "", "filename to pass in a pem formatted rsa key from aws kms or similar")

	// Other options which may be needed in the above
	flag.StringVar(&flCaCertFile, "cacert", "", "when signing a cert, you must provide the *pem* formatted parent certificate filename. this can also be defined in config.json.")
	flag.BoolVar(&flGenPrivKey, "genkey", false, "generate an rsa private key to be used in the operation, e.g. for import into another system.")
	flag.BoolVar(&flUsage, "usage", false, "show more detailed usage and examples.")
	flag.BoolVar(&flDebug, "debug", false, "show more stuff about what's happening.")
	// config
	flag.StringVar(&flConfig, "config", "config.json", "override the default config file to be used.")
	flag.IntVar(&flTtl, "ttl", 365, "override the default 365 days for an issued cert.")
	flag.BoolVar(&flShowVersion, "version", false, "Show version information, and quit.")
	flag.Parse()
	if flShowVersion {
		// Initialize basic logging for version output
		InitLogging(LogConfig{Level: "INFO", Format: "text"}, flDebug)
		logger := GetLogger()
		if buildstamp != "" && githash != "" {
			logger.Info("Version information",
				"version", version,
				"buildstamp", buildstamp,
				"githash", githash)
		} else {
			logger.Info("Version information",
				"version", version,
				"type", "release")
		}
		os.Exit(0)
	}
	if flUsage {
		usage()
		os.Exit(0)
	}
	// XDG_CONFIG_HOME=$HOME/.config by default.
	// try and load our config file from some locations....
	var confFile string
	if flConfig != "config.json" { // user has overridden default
		confFile = flConfig
		// Will log after logger is initialized
	} else if _, err := os.Stat(os.Getenv("XDG_CONFIG_HOME") + "/.certsquirt/config.json"); err == nil {
		confFile = os.Getenv("XDG_CONFIG_HOME") + "/.certsquirt/config.json"
	} else if _, err := os.Stat("config.json"); err == nil {
		confFile = "config.json"
	} else {
		// Initialize basic logging for error output before config is loaded
		InitLogging(LogConfig{Level: "ERROR", Format: "text"}, false)
		logger := GetLogger()
		logger.Error("Cannot find configuration file", 
			"default_config", flConfig,
			"suggestion", "specify config file with -config argument")
		os.Exit(1)
	}
	confJson, err := os.ReadFile(confFile)
	if err != nil {
		// Initialize basic logging for error output before config is loaded
		InitLogging(LogConfig{Level: "ERROR", Format: "text"}, false)
		logger := GetLogger()
		logger.Error("Cannot open configuration file", 
			"error", err, 
			"config_file", confFile)
		os.Exit(1)
	}
	err = json.Unmarshal(confJson, &config)
	if err != nil {
		// Initialize basic logging for error output before config is loaded  
		InitLogging(LogConfig{Level: "ERROR", Format: "text"}, false)
		logger := GetLogger()
		logger.Error("Malformed configuration file", 
			"error", err, 
			"config_file", confFile)
		os.Exit(1)
	}
	
	// Initialize structured logging
	logConfig := LogConfig{
		Level:     config.LogLevel,
		Format:    config.LogFormat,
		AuditFile: config.AuditLogFile,
	}
	InitLogging(logConfig, flDebug)
	
	logger := GetLogger()
	
	// Log which config file is being used
	if flConfig != "config.json" {
		logger.Info("Using config file specified on command line", 
			"config_file", confFile)
	} else if confFile == os.Getenv("XDG_CONFIG_HOME")+"/.certsquirt/config.json" {
		logger.Info("Using XDG config directory", 
			"config_file", confFile)
	} else {
		logger.Info("Using config file from current directory", 
			"config_file", confFile)
	}
	
	if flDebug {
		logger.Debug("Configuration loaded successfully", 
			"config_file", confFile,
			"config", config)
	}
	if flCaCertFile == "" && config.SigningCert != "" {
		// set flCaCertFile to use the defined file in the json config
		flCaCertFile = config.SigningCert
	}

	// right logically go through what the user might want to do...
	if flCSR != "" {
		logger.Info("Inspecting certificate signing request", "csr_file", flCSR)
		csr, err := loadCSR(flCSR)
		if err != nil {
			logger.Error("Certificate signing request is invalid", "error", err, "csr_file", flCSR)
			os.Exit(1)
		}
		// right.  don;t make a fatal mistake.
		err = csr.CheckSignature()
		if err != nil {
			logger.Error("SIGNATURE MISMATCH ON CSR - REFUSING TO CONTINUE", 
				"csr_file", flCSR, 
				"error", err)
			AuditEvent("csr_validation", false, 
				"csr_file", flCSR,
				"reason", "signature_mismatch")
			os.Exit(1)
		}
		AuditEvent("csr_validation", true, 
			"csr_file", flCSR,
			"subject", csr.Subject.CommonName)
		prettyPrintCSR(csr)
		if !flSubCa && !flSign {
			os.Exit(0)
		}
	}
	if !flCA && !flSubCa && !flSign && flCSR == "" {
		logger.Info("No operation specified - use -help for available options")
		usage()
		os.Exit(0)
	}

	// As we use DynamoDB, we will always need to auth to AWS to pop records there.
	creds := assumeRole()

	// the pkcs11 provider knows nothing about our credentials, indeed it is just a
	// library on disk - as a result we need to set our environment variables here,
	// so that future calls will use our new creds.
	// see: https://github.com/JackOfMostTrades/aws-kms-pkcs11#configuration
	os.Setenv("AWS_ACCESS_KEY_ID", *creds.AccessKeyId)
	os.Setenv("AWS_SECRET_ACCESS_KEY", *creds.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", *creds.SessionToken)
	os.Setenv("AWS_DEFAULT_REGION", "eu-west-1")
	// TODO AWS_ROLE_SESSION_NAME?

	// most likely we're being used to simply sign a csr, so start there...
	if flSign && flCSR != "" {
		logger.Info("Starting certificate signing operation", 
			"csr_file", flCSR,
			"ca_cert", flCaCertFile)
		
		csr, err := loadCSR(flCSR)
		if err != nil {
			logger.Error("Cannot load certificate signing request", 
				"error", err, 
				"csr_file", flCSR)
			os.Exit(1)
		}
		if flCaCertFile == "" {
			logger.Error("No signing CA certificate provided - use -cacert flag")
			os.Exit(1)
		}

		signingCert, err := loadPemCert(flCaCertFile)
		if err != nil {
			logger.Error("Cannot load CA certificate", 
				"error", err, 
				"ca_cert_file", flCaCertFile)
			os.Exit(1)
		}
		signer, err := initPkcs11(signingCert.PublicKey.(*rsa.PublicKey))
		if err != nil {
			logger.Error("PKCS11 configuration failed", 
				"error", err,
				"library_path", config.Path,
				"suggestions", []string{
					"Verify PKCS11 configuration file exists",
					"Check if hardware token is connected",
					"Confirm PKCS11 library path is accessible",
				})
			AuditEvent("pkcs11_init", false, 
				"error", err.Error(),
				"library_path", config.Path)
			os.Exit(1)
		}
		
		AuditEvent("certificate_signing_started", true,
			"csr_subject", csr.Subject.CommonName,
			"ca_subject", signingCert.Subject.CommonName)
			
		crtBytes, err := signCSR(signer, csr)
		if err != nil {
			logger.Error("Certificate signing failed", 
				"error", err,
				"csr_subject", csr.Subject.CommonName)
			AuditEvent("certificate_signing", false,
				"csr_subject", csr.Subject.CommonName,
				"error", err.Error())
			os.Exit(1)
		}
		
		certFilename := csr.Subject.CommonName
		logger.Info("Writing certificate files", 
			"subject", csr.Subject.CommonName,
			"pem_file", certFilename+".pem",
			"crt_file", certFilename+".crt")
			
		err = certToPem(crtBytes, certFilename+".pem")
		if err != nil {
			logger.Error("Cannot save PEM certificate file", 
				"error", err, 
				"filename", certFilename+".pem")
			os.Exit(1)
		}
		err = os.WriteFile(certFilename+".crt", crtBytes, 0644)
		if err != nil {
			logger.Error("Cannot save CRT certificate file", 
				"error", err, 
				"filename", certFilename+".crt")
			os.Exit(1)
		}
		
		AuditEvent("certificate_signing", true,
			"csr_subject", csr.Subject.CommonName,
			"ca_subject", signingCert.Subject.CommonName,
			"pem_file", certFilename+".pem",
			"crt_file", certFilename+".crt")
			
		logger.Info("Certificate signed successfully", 
			"subject", csr.Subject.CommonName,
			"pem_file", certFilename+".pem",
			"crt_file", certFilename+".crt")
		os.Exit(0)
	}
	// catch a missing public key
	if flCA && flBootstrap && flPubKey == "" {
		logger.Error("Public key required for root CA bootstrap operation - use -pubkey flag")
		os.Exit(1)
	}
	if flCA && flBootstrap && flPubKey != "" {
		logger.Warn("ROOT CA BOOTSTRAP OPERATION REQUESTED")
		logger.Warn("DO NOT PROCEED UNLESS YOU ARE ABSOLUTELY SURE")
		logger.Warn("YOU WANT TO CREATE A NEW ROOT CA")
		logger.Warn("Hit Ctrl+C to cancel this operation")
		logger.Info("Waiting 5 seconds before proceeding...")

		time.Sleep(5 * time.Second)
		// stop this being used in a script via `expect' or similar
		challengeString, err := password.Generate(20, 2, 0, false, false)
		if err != nil {
			logger.Error("Cannot generate challenge string", "error", err)
			os.Exit(1)
		}
		var challengeResponse string

		logger.Info("Authentication challenge required")
		logger.Info("Enter the following text *exactly* as it is shown:")
		fmt.Printf("\t\t%v\n", challengeString)
		fmt.Printf("\t\tRESPONSE: -> ")
		fmt.Scanln(&challengeResponse)
		if strings.Compare(challengeResponse, challengeString) != 0 {
			logger.Error("INCORRECT CHALLENGE RESPONSE - OPERATION CANCELLED")
			AuditEvent("root_ca_bootstrap", false, 
				"reason", "challenge_failed",
				"pubkey_file", flPubKey)
			os.Exit(10)
		}
		// flPubKey should point to a file on disk we can consume to grab out the rsa public key, to allow us to find the
		// corresponding signer...
		pubkey, err := loadPubKey(flPubKey)
		if err != nil {
			logger.Error("Cannot load public key", "error", err, "pubkey_file", flPubKey)
			os.Exit(1)
		}
		if flDebug {
			logger.Debug("Loading matching private key", 
				"pubkey_type", fmt.Sprintf("%T", pubkey),
				"pubkey_file", flPubKey)
		}

		signer, err := initPkcs11(pubkey.(*rsa.PublicKey))
		if err != nil {
			logger.Error("PKCS11 initialization failed for root CA bootstrap", 
				"error", err,
				"pubkey_file", flPubKey,
				"troubleshooting", []string{
					"Check PIN is correct",
					"Verify slot number is correct", 
					"Confirm PKCS11 library path",
					"For KMS: set AWS_KMS_PKCS11_DEBUG=1",
					"For YubiKey: set YKCS11_DBG=9 or YKCS11_DBG=1",
				})
			AuditEvent("root_ca_bootstrap", false,
				"reason", "pkcs11_init_failed",
				"pubkey_file", flPubKey,
				"error", err.Error())
			os.Exit(1)
		}
		
		AuditEvent("root_ca_bootstrap", true,
			"operation", "started",
			"pubkey_file", flPubKey)
			
		ok := createRootCA(signer)
		if ok {
			logger.Info("Root CA created successfully")
			AuditEvent("root_ca_bootstrap", true,
				"operation", "completed",
				"pubkey_file", flPubKey)
			os.Exit(0)
		} else {
			logger.Error("Root CA creation failed unexpectedly")
			AuditEvent("root_ca_bootstrap", false,
				"reason", "creation_failed",
				"pubkey_file", flPubKey)
			os.Exit(1)
		}
	}
	if flSubCa && flPubKey != "" && !flGenPrivKey {
		if flInterName == "" {
			logger.Error("SubCA friendly name required - use -subcaname flag (e.g. -subcaname 'Apple TV Devices')")
			os.Exit(1)
		}
		if flCaCertFile == "" {
			logger.Error("Signing CA certificate required - use -cacert flag")
			os.Exit(1)
		}

		logger.Info("Creating intermediate CA certificate",
			"subca_name", flInterName,
			"pubkey_file", flPubKey,
			"ca_cert_file", flCaCertFile)

		pubkey, err := loadPubKey(flPubKey)
		if err != nil {
			logger.Error("Cannot load public key for SubCA", 
				"error", err, 
				"pubkey_file", flPubKey)
			os.Exit(1)
		}

		signingCert, err := loadPemCert(flCaCertFile)
		if err != nil {
			logger.Error("Cannot load signing CA certificate", 
				"error", err, 
				"ca_cert_file", flCaCertFile)
			os.Exit(1)
		}
		signer, err := initPkcs11(signingCert.PublicKey.(*rsa.PublicKey))
		if err != nil {
			logger.Error("PKCS11 initialization failed for SubCA creation", 
				"error", err)
			AuditEvent("subca_creation", false,
				"subca_name", flInterName,
				"reason", "pkcs11_init_failed",
				"error", err.Error())
			os.Exit(1)
		}
		
		AuditEvent("subca_creation", true,
			"operation", "started",
			"subca_name", flInterName,
			"ca_subject", signingCert.Subject.CommonName)
			
		_, ok := createIntermediateCert(signer, pubkey, flInterName)
		if !ok {
			logger.Error("SubCA certificate creation failed", 
				"subca_name", flInterName)
			AuditEvent("subca_creation", false,
				"subca_name", flInterName,
				"reason", "creation_failed")
			os.Exit(1)
		}
	}

	// perhaps we've been asked to create a new subca and generate a privkey
	if flSubCa && flGenPrivKey && flPubKey == "" {
		logger.Error("Signing key required for SubCA with generated private key - use -pubkey flag")
		os.Exit(1)
	}
	if flSubCa && flGenPrivKey && flPubKey != "" {
		if flInterName == "" {
			logger.Error("SubCA friendly name required - use -subcaname flag (e.g. -subcaname 'Apple TV Devices')")
			os.Exit(1)
		}
		
		logger.Info("Creating SubCA with generated private key",
			"subca_name", flInterName,
			"signing_key_file", flPubKey)
		// Generate a new RSA key.
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			logger.Error("Cannot generate RSA private key", "error", err)
			os.Exit(1)
		}
		// this is our newly generated public key
		newpubkey := key.Public()
		// this is our signing public key
		pubkey, err := loadPubKey(flPubKey)
		if err != nil {
			logger.Error("Cannot load signing public key", "error", err, "pubkey_file", flPubKey)
			os.Exit(1)
		}

		signer, err := initPkcs11(pubkey.(*rsa.PublicKey))
		if err != nil {
			logger.Error("PKCS11 initialization failed", "error", err)
			AuditEvent("subca_with_genkey", false,
				"subca_name", flInterName,
				"reason", "pkcs11_init_failed",
				"error", err.Error())
			os.Exit(1)
		}
		
		AuditEvent("subca_with_genkey", true,
			"operation", "started",
			"subca_name", flInterName)
			
		caName, ok := createIntermediateCert(signer, newpubkey, flInterName)
		if !ok {
			logger.Error("SubCA certificate creation failed", "subca_name", flInterName)
			AuditEvent("subca_with_genkey", false,
				"subca_name", flInterName,
				"reason", "cert_creation_failed")
			os.Exit(1)
		}

		keypassword, err = password.Generate(20, 2, 0, false, false)
		if err != nil {
			logger.Error("Cannot generate key password", "error", err)
			os.Exit(1)
		}
		file, err := os.OpenFile(caName+".key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			logger.Error("Cannot create private key file", 
				"error", err, 
				"filename", caName+".key")
			os.Exit(1)
		}
		// write out PEM wrapped key
		privPEMBlock, err := x509.EncryptPEMBlock(
			rand.Reader,
			"PRIVATE KEY",
			x509.MarshalPKCS1PrivateKey(key),
			[]byte(keypassword),
			x509.PEMCipher3DES, // PEMCipherAES256 prefereable but interopability reigns supreme...
		)
		if err != nil {
			logger.Error("Cannot encrypt private key", "error", err)
			os.Exit(1)
		}
		err = pem.Encode(file, privPEMBlock)
		if err != nil {
			logger.Error("Cannot write private key file", "error", err)
			os.Exit(1)
		}
		file.Close()
		
		logger.Info("SubCA with generated private key created successfully",
			"ca_name", caName,
			"key_file", caName+".key",
			"cert_file", caName+".pem")
		logger.Warn("PRIVATE KEY PASSPHRASE (store securely)", "passphrase", keypassword)
		logger.Info("To convert to PKCS12 format, use:",
			"command", fmt.Sprintf("openssl pkcs12 -export -out '%v.pkcs12' -inkey '%v.key' -in '%v.pem'", caName, caName, caName))
			
		AuditEvent("subca_with_genkey", true,
			"operation", "completed",
			"subca_name", flInterName,
			"ca_name", caName,
			"key_file", caName+".key")
			
	} else if flSubCa && !flGenPrivKey && flPubKey == "" {
		logger.Error("PEM formatted public key required for SubCA, or use -genkey flag to generate private key")
	}
	logger.Info("Operation completed successfully")
}
