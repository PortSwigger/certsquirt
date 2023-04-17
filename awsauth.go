package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/aws/aws-sdk-go/service/sts/stsiface"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"golang.org/x/term"
)

// TakeRole gets temporary security credentials to access resources
// Inputs:
//
//	svc is an AWS STS service client
//	roleARN is the Amazon Resource Name (ARN) of the role to assume
//	sessionName is a unique identifier for the session
//	mfaserial is the ARN of the MFA token you are using
//	mfacode is the code produced by the seed
//
// Output:
//
//	If success, information about the assumed role and nil
//	Otherwise, nil and an error from the call to AssumeRole
func TakeRole(svc stsiface.STSAPI, roleARN, sessionName *string, mfaserial *string, mfacode *string) (*sts.AssumeRoleOutput, error) {
	// snippet-start:[sts.go.take_role.call]

	// 🙁, this leaves an attacker a small window of opportunity.
	// Would be nice if AWS exposed an InvalidateCredentials() call.
	var duration int64 = 900 // minimum accepted by aws api
	result, err := svc.AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         roleARN,
		RoleSessionName: sessionName,
		SerialNumber:    mfaserial,
		TokenCode:       mfacode,
		DurationSeconds: &duration,
	})
	// snippet-end:[sts.go.take_role.call]

	return result, err
}

// nice wrapper to deal with command line copy pasta of credentials
func credentials() (string, string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Access Key ID: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Enter Access Key Secret: ")
	bytePassword, err := term.ReadPassword(0)
	if err != nil {
		log.Printf("ERROR: how the hell did you break that? (%v)", err)
		os.Exit(1)
	}
	fmt.Println()
	fmt.Printf("Enter MFA Code: ")
	byteMfaCode, err := term.ReadPassword(0)
	if err != nil {
		log.Printf("ERROR: how the hell did you break that? (%v)", err)
		os.Exit(1)
	}
	password := string(bytePassword)
	mfacode := string(byteMfaCode)

	return strings.TrimSpace(username), strings.TrimSpace(password), strings.TrimSpace(mfacode)
}

func assumeRole() (creds sts.Credentials) {
	var mfacode string
	if flDebug {
		log.Printf("DEBUG: Auth credentials to be used are: AccessKey(%v), SecretKey(%v), TotpSeed(%v)", config.AwsAccessKey, config.AwsSecretKey, config.AwsTotpSecret)
	}
	// if any of the creds are unset, then force all to be entered.
	if config.AwsAccessKey == "" || config.AwsSecretKey == "" || config.AwsTotpSecret == "" {
		//awsAccessKey, awsSecretKey, mfacode = credentials()
		config.AwsAccessKey, config.AwsSecretKey, mfacode = credentials()
	} else {
		if config.UseKms {
			// User wants to use kms, perhaps we should Fatalf here.
			log.Printf("WARNING: YOU ARE USING HARDCODED CREDENTIALS - THIS IS EXTREMELY DANGEROUS")
		}
	}
	// set them in our env so that they are used below, overwritting anything that already
	// exists
	os.Setenv("AWS_ACCESS_KEY", config.AwsAccessKey)
	os.Setenv("AWS_SECRET_KEY", config.AwsSecretKey)
	os.Setenv("AWS_DEFAULT_REGION", config.AwsRegion)
	// defined role we want to assume
	// get the current user to popilate the sessionName with
	user, err := user.Current()
	if err != nil {
		log.Fatalf("FATAL: Could not figure out username (%v)", err)
	}
	// now figure out the hostname to add to the sessionName to track via cloudtrail
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("FATAL: Could not figure out hostname (%v)", err)
	}
	sessionName := user.Username + "@" + hostname

	// perhaps don't do this for production....
	if config.AwsTotpSecret != "" {
		log.Printf("WARNING: YOU ARE USING HARDCODED TOTP SECRET - THIS IS EXTREMELY DANGEROUS")
		mfacode, err = totp.GenerateCodeCustom(config.AwsTotpSecret, time.Now(), totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1, // yep, sha1.
		})
		if err != nil {
			log.Fatalf("FATAL: Could not generate TOTP code from secret in configuration (%v)", err)
		}
	}

	// snippet-start:[sts.go.take_role.session]
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := sts.New(sess)
	// snippet-end:[sts.go.take_role.session]

	result, err := TakeRole(svc, &config.AwsRoleARN, &sessionName, &config.AwsMfaSerial, &mfacode)
	if err != nil {
		log.Fatalf("Got an error assuming the role: %v (perhaps mfa timing issue? try again)", err)
		return
	}
	return *result.Credentials
}
