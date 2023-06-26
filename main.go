package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "embed"

	"github.com/sethvargo/go-password/password"
)

type Config struct {
	Organisation   string `json:""`
	Country        string `json:""`
	CaName         string `json:""`
	CaVersion      string `json:""`
	CaAiaIssuerURL string `json:""`
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
}

var config Config

// command line flags/arguments
var flShowVersion, flCA, flSign, flSubCa, flBootstrap, flUsage, flDebug, flGenPrivKey, flOcspSigner bool
var flCSR, flPubKey, flCaCertFile, flInterName, flConfig string

var keypassword string
var buildstamp, githash string // For versioning, via go build -v -x -a -ldflags "-X main.buildstamp=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.githash=`git rev-parse HEAD`" || exit'`

//go:embed VERSION
var version string

func main() {
	var err error
	/* Log better */
	log.SetFlags(log.LstdFlags | log.Ldate | log.Lmicroseconds | log.Lshortfile)
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
	flag.BoolVar(&flShowVersion, "version", false, "Show version information, and quit.")
	flag.Parse()
	if flShowVersion {
		if buildstamp != "" && githash != "" {
			log.Printf("VERSION: Running version %v built at %v. (githash: %v)", version, buildstamp, githash)
		} else {
			log.Printf("VERSION: Running release version %v", version)
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
		log.Printf("INFO: Using %v as my config, as specified on command line arguments", flConfig)
		confFile = flConfig
	} else if _, err := os.Stat(os.Getenv("XDG_CONFIG_HOME") + "/.certsquirt/config.json"); err == nil {
		log.Printf("INFO: Using configuration found in %v", os.Getenv("XDG_CONFIG_HOME")+"/.certsquirt/config.json")
		confFile = os.Getenv("XDG_CONFIG_HOME") + "/.certsquirt/config.json"
	} else if _, err := os.Stat("config.json"); err == nil {
		log.Printf("INFO: Using config.json in current directory.")
		confFile = "config.json"
	} else {
		log.Fatalf("FATAL: I can't find my configuration file, specify one with -config argument (default: %v)", flConfig)
	}
	confJson, err := os.ReadFile(confFile)
	if err != nil {
		log.Fatalf("FATAL: Couldn't open config file %v (%v)", confFile, err)
	}
	err = json.Unmarshal(confJson, &config)
	if err != nil {
		log.Fatalf("FATAL: malformed config file %v (%v)", confFile, err)
	}
	if flDebug {
		log.Printf("DEBUG: Config is %#v (config file used is %v)", config, confFile)
	}
	if flCaCertFile == "" && config.SigningCert != "" {
		// set flCaCertFile to use the defined file in the json config
		flCaCertFile = config.SigningCert
	}

	// right logically go through what the user might want to do...
	if flCSR != "" {
		log.Printf("Inspecting csr in file %v", flCSR)
		csr, err := loadCSR(flCSR)
		if err != nil {
			log.Fatalf("ERROR: csr looks bad (%v)", err)
		}
		// right.  don;t make a fatal mistake.
		err = csr.CheckSignature()
		if err != nil {
			log.Fatalf("DANGER: SIGNATURE MISMATCH ON CSR.  REFUSING TO CONTINUE.")
		}
		prettyPrintCSR(csr)
		if !flSubCa && !flSign {
			os.Exit(0)
		}
	}
	if !flCA && !flSubCa && !flSign && flCSR == "" {
		log.Printf("You haven't told me to do anything sensible.  Try -help")
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
		// func signCSR(ctx crypto11.Context, csr *x509.CertificateRequest) (crtBytes []byte, err error)
		csr, err := loadCSR(flCSR)
		if err != nil {
			log.Fatalf("FATAL: I can't load this csr (%v)", err)
		}
		if flCaCertFile == "" {
			log.Fatalf("FATAL: Please provide the *signing* CA certificate via the -cacert flag.")
		}

		signingCert, err := loadPemCert(flCaCertFile)
		if err != nil {
			log.Fatalf("FATAL: Couldn't load CA x509 certificate from %v", flCaCertFile)
		}
		signer, err := initPkcs11(signingCert.PublicKey.(*rsa.PublicKey))
		if err != nil {
			log.Printf("FATAL: Could not not configure p11 - did you create or specify the configuration file, ")
			log.Printf("FATAL: as detailed at https://pkg.go.dev/github.com/ThalesIgnite/crypto11#ConfigureFromFile ?")
			log.Printf("FATAL: Starting at Layer 1, if you are using a yubikey or hardware token, is it plugged in??")
			log.Printf("FATAL: *** Check if the configured pkcs11 library (%v) is accessible?", config.Path)
			log.Fatalf("FATAL: %v", err)
		}
		crtBytes, err := signCSR(signer, csr)
		if err != nil {
			log.Fatalf("FATAL: %v", err)
		}
		log.Printf("INFO: Writing pem certificate to %v.pem", csr.Subject.CommonName)
		err = certToPem(crtBytes, csr.Subject.CommonName+".pem")
		if err != nil {
			log.Fatalf("ERROR: couldn't save %v.pem file! (%v)", csr.Subject.CommonName, err)
		}
		log.Printf("INFO: Writing crt certificate to %v.crt", csr.Subject.CommonName)
		err = os.WriteFile(csr.Subject.CommonName+".crt", crtBytes, 0644)
		if err != nil {
			log.Fatalf("ERROR: couldn't save %v.crt file! (%v)", csr.Subject.CommonName, err)
		}
		os.Exit(0)
	}
	// catch a missing public key
	if flCA && flBootstrap && flPubKey == "" {
		log.Fatalf("FATAL: you need to pass in a public key for this operation via -pubkey")
	}
	if flCA && flBootstrap && flPubKey != "" {
		log.Printf("***************** WARNING ***************")
		log.Printf("****  DO NOT PROCEED UNLESS YOU ARE  ****")
		log.Printf("*** ABSOLUTELY SURE YOU WANT TO MINT ****")
		log.Printf("***   A NEW ROOT CA.  Hit Ctrl+c to  ****")
		log.Printf("***       CANCEL THIS OPERATION      ****")
		log.Printf("***************** WARNING ***************")
		log.Printf("")
		log.Printf("    ....Sleeping for 5 seconds....")

		time.Sleep(5 * time.Second)
		// stop this being used in a script via `expect' or similar
		challengeString, err := password.Generate(20, 2, 0, false, false)
		if err != nil {
			log.Fatalf("FATAL: could not generate challenge (%v)", err)
		}
		var challengeResponse string

		log.Println()
		log.Println("Enter the following text *exactly* as it is shown")
		log.Printf("\t\t%v\n", challengeString)
		fmt.Printf("\t\tRESPONSE: -> ")
		fmt.Scanln(&challengeResponse)
		if strings.Compare(challengeResponse, challengeString) != 0 {
			log.Printf("INCORRECT CHALLENGE RESPONSE, BAILING OUT")
			os.Exit(10)
		}
		// flPubKey should point to a file on disk we can consume to grab out the rsa public key, to allow us to find the
		// corresponding signer...
		pubkey, err := loadPubKey(flPubKey)
		if err != nil {
			log.Fatalf("FATAL: %v", err)
		}
		if flDebug {
			log.Printf("DEBUG: Will attempt to load matching private key of type %T for %#v", pubkey, pubkey)
		}

		signer, err := initPkcs11(pubkey.(*rsa.PublicKey))
		if err != nil {
			log.Printf("ERROR: %v", err)
			log.Printf("INFO: This could be down to several reasons, incorrect pin, wrong slot specified, pkcs11.so library incorrectly set,")
			log.Printf("INFO: the key doesn't exist, etc.  If using KMS try setting AWS_KMS_PKCS11_DEBUG=1 in the environment.  ")
			log.Printf("INFO: For the Yubikey, try setting YKCS11_DBG=9 (full debug) or YKCS11_DBG=1(minimal debug).  Other libraries")
			log.Printf("INFO: will likely have similar debugging features.")
			log.Fatalf("FATAL: cannot continue sorry")
		}
		ok := createRootCA(signer)
		if ok {
			log.Printf("OK: DONE!")
			os.Exit(0)
		} else {
			log.Fatalf("FATAL: Something unexpected went wrong...")
		}
	}
	if flSubCa && flPubKey != "" && !flGenPrivKey {
		if flInterName == "" {
			log.Fatalf("ERROR: You need to pass a 'friendly' name for this CA via the -subcaname option (e.g. -subcaname 'Apple TV Devices') ")
		}
		if flCaCertFile == "" {
			log.Fatalf("FATAL: Please provide the *signing* CA certificate via the -cacert flag.")
		}

		pubkey, err := loadPubKey(flPubKey)
		if err != nil {
			log.Fatalf("FATAL: %v", err)
		}

		signingCert, err := loadPemCert(flCaCertFile)
		if err != nil {
			log.Fatalf("FATAL: Couldn't load CA x509 certificate from %v", flCaCertFile)
		}
		signer, err := initPkcs11(signingCert.PublicKey.(*rsa.PublicKey))
		_, ok := createIntermediateCert(signer, pubkey, flInterName)
		if !ok {
			log.Fatalf("FATAL: When creating certificate (%v)", err)
		}
	}

	// perhaps we've been asked to create a new subca and generate a privkey
	if flSubCa && flGenPrivKey && flPubKey == "" {
		log.Fatalf("ERROR: Please pass me the signing key for this operation via -pubkey so I can figure out which one to use.")
	}
	if flSubCa && flGenPrivKey && flPubKey != "" {
		if flInterName == "" {
			log.Fatalf("ERROR: You need to pass a 'friendly' name for this CA via the -subcaname option (e.g. -subcaname 'Apple TV Devices') ")
		}
		// Generate a new RSA key.
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Fatalf("FATAL: Could not generate rsa private key (%v)", err)
		}
		// this is our newly generated public key
		newpubkey := key.Public()
		// this is our signing public key
		pubkey, err := loadPubKey(flPubKey)
		if err != nil {
			log.Fatalf("FATAL: %v", err)
		}

		signer, err := initPkcs11(pubkey.(*rsa.PublicKey))
		if err != nil {
			log.Fatalf("FATAL: %v", err)
		}
		caName, ok := createIntermediateCert(signer, newpubkey, flInterName)
		if !ok {
			log.Fatalf("FATAL: When creating certificate (%v)", err)
		}

		keypassword, err = password.Generate(20, 2, 0, false, false)
		if err != nil {
			log.Fatalf("FATAL: could not generate password (%v)", err)
		}
		file, err := os.OpenFile(caName+".key", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
		if err != nil {
			log.Printf("FATAL: %v", err)
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
			log.Fatalf("FATAL: %v", err)
		}
		err = pem.Encode(file, privPEMBlock)
		if err != nil {
			log.Fatalf("FATAL: writing private key (%v)", err)
		}
		log.Println()
		log.Printf("INFO: Done.  File %v.key is pem file containing wrapped private key.", caName)
		log.Println()
		log.Printf("SECRET: Private key is wrapped with this passphrase: %v", keypassword)
		log.Println()
		log.Printf("INFO: To convert this to PKCS12 (for use in systems that require it), try running")
		log.Printf("\t\t\topenssl pkcs12 -export -out '%v.pkcs12' -inkey '%v.key' -in '%v.pem'", caName, caName, caName)
	} else if flSubCa && !flGenPrivKey && flPubKey == "" {
		log.Printf("ERROR: You need to pass me a pem formatted public key to use for the Sub-CA")
		log.Printf("ERROR: Alternatively pass me the -genkey flag to have me generate the private key")
	}
	log.Printf("INFO: Clean exit.")
}
