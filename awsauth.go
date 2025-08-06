package main

import (
	"bufio"
	"fmt"
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
	logger := GetLogger()
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Access Key ID: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Enter Access Key Secret: ")
	bytePassword, err := term.ReadPassword(0)
	if err != nil {
		logger.Error("Failed to read access key secret", "error", err)
		os.Exit(1)
	}
	fmt.Println()
	fmt.Printf("Enter MFA Code: ")
	byteMfaCode, err := term.ReadPassword(0)
	if err != nil {
		logger.Error("Failed to read MFA code", "error", err)
		os.Exit(1)
	}
	password := string(bytePassword)
	mfacode := string(byteMfaCode)

	return strings.TrimSpace(username), strings.TrimSpace(password), strings.TrimSpace(mfacode)
}

func assumeRole() (creds sts.Credentials) {
	logger := GetLogger()
	var mfacode string
	if flDebug {
		logger.Debug("Authentication credentials configuration", 
			"has_access_key", config.AwsAccessKey != "",
			"has_secret_key", config.AwsSecretKey != "",
			"has_totp_secret", config.AwsTotpSecret != "")
	}
	// if any of the creds are unset, then force all to be entered.
	if config.AwsAccessKey == "" || config.AwsSecretKey == "" || config.AwsTotpSecret == "" {
		logger.Info("Interactive credential input required")
		config.AwsAccessKey, config.AwsSecretKey, mfacode = credentials()
	} else {
		// User wants to use kms, perhaps we should Fatalf here.
		logger.Warn("HARDCODED CREDENTIALS DETECTED - THIS IS EXTREMELY DANGEROUS FOR PRODUCTION USE")
		AuditEvent("hardcoded_credentials_used", true,
			"warning", "hardcoded AWS credentials in configuration")
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
		logger.Error("Cannot determine current username for session", "error", err)
		os.Exit(1)
	}
	// now figure out the hostname to add to the sessionName to track via cloudtrail
	hostname, err := os.Hostname()
	if err != nil {
		logger.Error("Cannot determine hostname for session", "error", err)
		os.Exit(1)
	}
	sessionName := user.Username + "@" + hostname

	// perhaps don't do this for production....
	if config.AwsTotpSecret != "" {
		logger.Warn("HARDCODED TOTP SECRET DETECTED - THIS IS EXTREMELY DANGEROUS FOR PRODUCTION USE")
		mfacode, err = totp.GenerateCodeCustom(config.AwsTotpSecret, time.Now(), totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1, // yep, sha1.
		})
		if err != nil {
			logger.Error("Cannot generate TOTP code from configuration secret", "error", err)
			os.Exit(1)
		}
		AuditEvent("hardcoded_totp_used", true,
			"warning", "hardcoded TOTP secret used for authentication")
	}

	// snippet-start:[sts.go.take_role.session]
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := sts.New(sess)
	// snippet-end:[sts.go.take_role.session]

	logger.Info("Assuming AWS role", 
		"role_arn", config.AwsRoleARN,
		"session_name", sessionName,
		"mfa_serial", config.AwsMfaSerial)
		
	result, err := TakeRole(svc, &config.AwsRoleARN, &sessionName, &config.AwsMfaSerial, &mfacode)
	if err != nil {
		logger.Error("Failed to assume AWS role", 
			"error", err,
			"role_arn", config.AwsRoleARN,
			"session_name", sessionName,
			"suggestion", "check MFA timing or try again")
		AuditEvent("aws_role_assumption", false,
			"role_arn", config.AwsRoleARN,
			"session_name", sessionName,
			"error", err.Error())
		os.Exit(1)
	}
	
	logger.Info("Successfully assumed AWS role", 
		"role_arn", config.AwsRoleARN,
		"session_name", sessionName)
	AuditEvent("aws_role_assumption", true,
		"role_arn", config.AwsRoleARN,
		"session_name", sessionName)
		
	return *result.Credentials
}
