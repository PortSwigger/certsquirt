package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/pkg/errors"
)

var dyndb *dynamodb.DynamoDB

type x509Record struct {
	Status             string
	Requester          string
	SerialNumber       string
	Issuer             string
	Subject            string
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	SignatureAlgorithm x509.SignatureAlgorithm
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []net.IP
	URIs               []*url.URL
	PubKey             []byte
	DerCert            []byte
}

func addDbRecord(crtBytes []byte) error {
	logger := GetLogger()
	// now parse the cert back and add it to the DB.
	crt, err := x509.ParseCertificate(crtBytes)
	if err != nil {
		logger.Error("Cannot parse certificate for database record", "error", err)
		return err
	}
	// chomp out the pub key bytes
	var pubBytes []byte
	switch pub := crt.PublicKey.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(*pub)
		if err != nil {
			return err
		}
	case *ecdsa.PublicKey:
		pubBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	default:
		return errors.New("only ECDSA and RSA public keys are supported")
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Requester in the format of \"Joe Blogs <j.blogs@foo.com>\" ->   ")
	requester, _ := reader.ReadString('\n')
	// marshal the crt to a pem byte array
	record := x509Record{
		Status:             "V", // Valid
		Requester:          requester,
		SerialNumber:       crt.SerialNumber.String(), // serial number should be unique (as in cryptographically) so we can use this as the key
		Issuer:             crt.Issuer.String(),
		Subject:            crt.Subject.String(),
		NotBefore:          crt.NotBefore,
		NotAfter:           crt.NotAfter,
		PublicKeyAlgorithm: crt.PublicKeyAlgorithm,
		SignatureAlgorithm: crt.SignatureAlgorithm,
		DNSNames:           crt.DNSNames,
		EmailAddresses:     crt.EmailAddresses,
		IPAddresses:        crt.IPAddresses,
		URIs:               crt.URIs,
		PubKey:             pubBytes,
		DerCert:            crtBytes,
	}

	// we should be running under the role given to us by the sts tokens.
	// We'll just use this role to create a new session.
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Region: aws.String(config.AwsRegion)},
	})
	if err != nil {
		logger.Error("Cannot create AWS session for database", 
			"error", err, 
			"region", config.AwsRegion)
		return err
	}
	dyndb = dynamodb.New(sess)
	av, err := dynamodbattribute.MarshalMap(record)
	if err != nil {
		logger.Error("Cannot marshal certificate record for database", 
			"error", err,
			"subject", crt.Subject.CommonName)
		return err
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(config.AwsDbTableName),
	}
	
	logger.Debug("Adding certificate to database", 
		"table", config.AwsDbTableName,
		"subject", crt.Subject.CommonName,
		"serial", crt.SerialNumber.String())
		
	_, err = dyndb.PutItem(input)
	if err != nil {
		logger.Error("Cannot add certificate to database", 
			"error", err,
			"table", config.AwsDbTableName,
			"subject", crt.Subject.CommonName,
			"serial", crt.SerialNumber.String())
		return err
	}

	logger.Info("Certificate successfully added to database", 
		"table", config.AwsDbTableName,
		"subject", crt.Subject.CommonName,
		"serial", crt.SerialNumber.String(),
		"requester", strings.TrimSpace(record.Requester))
		
	AuditEvent("certificate_database_add", true,
		"subject", crt.Subject.CommonName,
		"serial", crt.SerialNumber.String(),
		"table", config.AwsDbTableName,
		"requester", strings.TrimSpace(record.Requester))

	return nil
}
