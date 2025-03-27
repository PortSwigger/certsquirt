# A golang PKI in just over a 1000 lines of code.

[![Build Status](https://github.com/PortSwigger/certsquirt/actions/workflows/main.yml/badge.svg)](https://github.com/PortSwigger/certsquirt/actions/workflows/main.yml)
[![GHCR](https://img.shields.io/badge/GHCR-certsquirt-blue?logo=docker)](https://github.com/orgs/portswigger/packages/container/package/certsquirt)
[![Latest Release](https://img.shields.io/github/v/release/portswigger/certsquirt)](https://github.com/portswigger/certsquirt/releases)
[![License](https://img.shields.io/github/license/portswigger/certsquirt)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/portswigger/certsquirt)](https://goreportcard.com/report/github.com/portswigger/certsquirt)
[![CodeQL](https://github.com/PortSwigger/certsquirt/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/PortSwigger/certsquirt/actions/workflows/github-code-scanning/codeql/)

# Introduction

This repository contains a solution to create and manage a small-scale PKI for a small or medium sized enterprise, which is managed securely with keys being managed by a PKCS11 provider.  This is an easier solution to drive than something like easy-rsa, is more secure, and is far simpler to configure than other PKI software solutions.

While there are native API's to talk to crypto providers, for example KMS,  directly one of the goals of this project was to make things configurable, so that you are not tied to a single crypto provider.  To that end, we chose to use [pkcs11](https://en.wikipedia.org/wiki/PKCS_11) as a crypto provider.  This means you should theoretically be able to talk to ['real world' HSM's](https://github.com/ThalesIgnite/crypto11#testing-with-thales-luna-hsm), [AWS CloudHSM](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html), [YubiKeys](https://developers.yubico.com/yubico-piv-tool/YKCS11/) , et al.  

This effectively gives you an excellent starting point to expand your crypto world as you progress - you should be able to start with Yubikeys or AWS KMS and then as requirements dictate, migrate upwards to more robust crypto providers.  You could mix and match, for example the root in KMS and a YubiKey for issuing certificates, or a Yubikey for root and KMS for the subca issuing, or just 2 Yubikeys, though for testing all you need is 1.

# Caveats

Although not an issue with this solution per se, if you intend to use the `aws-kms-pkcs11` provider, this does not build easily on MacOS.  You are advised to use a Linux machine/VM to run this solution if you wish to use KMS.  

## Docker
There is also a docker image which you can use, based on ubuntu, on the 'releases' page of the github.

You can run it like this - note you will need to map `somedir` to `depot`, with somedir containing the config and artifacts you need, e.g. 
**FIXME**
```
docker run -v somedir:/depot/ --platform linux/x86_64 -w /depot -it ghcr.io/portswigger/certsquirt:main -config /depot/config.json.prod  -ca -bootstrap  -pubkey /depot/some_kms_root_ca_pubkey.pub
```

```
docker pull ghcr.io/portswigger/certsquirt:linux-arm64
```

#

If you wish to use Yubikeys as the provider, then this works rather well with MacOS.

As is usual, mostly everything works with Linux.

# Configuration

Configuration is performed via a JSON config file.  By default, we will attempt to load a file name config.json in the current directory.

A sample is available [here](https://raw.githubusercontent.com/PortSwigger/certsquirt/main/config.json.sample).

You will need to edit the config file to (at a bare minimum) configure the following:

* AwsRoleARN
* AwsMfaSerial
* AwsDbTableName
* AwsRegion
* P11Path
* P11TokenLabel (Use "" for a Yubikey, or try "" if having problems)
* P11Pin (Add the pin for a Yubikey, leave as "" for AWS KMS)
* P11Slot (Leave as 0 for both KMS and Yubikeys)

If using KMS, you will need to install and configure [aws-kms-pkcs11](#jack-of-most-trades---aws-kms-pkcs11).  The P11TokenLabel corresponds to the label defined in the aws-kms-pkcs11 [configuration file](https://github.com/JackOfMostTrades/aws-kms-pkcs11#configuration) .  You will need to have this configured and working before you can proceed.  You can ignore the part around 'AWS Credentials' - we'll handle that for you.

# Installation

Either clone this repository with git and run `make`, or you can install it via 

`go install github.com/PortSwigger/certsquirt@latest`

At a minimum, you will need to create a DynamoDB table within AWS.  The  [cloudformation](https://github.com/PortSwigger/certsquirt/blob/main/cloudformation/certsquirt.yaml) template can be editted to remove references to KMS keys if you are going to use something else as a crypto provider, otherwise the default will create everything you need to host the keys and DB in AWS.  See [here](#cloudformation) for more details.

# Execution

## Yubikey

Yubikeys are awesome devices, and have a massive scope for usage in crypto problem solving.  Here's a guide to how to set up using a Yubikey for one of the crypto providers.

*note: you will still need to use AWS DynamoDB as the backend database!  Simply comment out the KMS key generations in the cloudformation template provided*

To use the yubikey, you will need to install the `yubico-piv-tool` via your package manager (it's in homebrew on MacOS), or by following the instructions at [Yubico PIV Guide](https://developers.yubico.com/yubico-piv-tool/).

The Yubikey has multiple key slots available for use, described fully [here](https://developers.yubico.com/PIV/Introduction/Certificate_slots.html).  There are exposed slots which are now 'retired' by Yubico, living in slots 82-95.  In the following example we are using slot 88 to generate an RSA2048 key.  Please be careful - the tool doesn't prompt you if you are about to overwrite an existing key!  With that said, it's extremely unlikely anything is in slot 88 unless you've done this before, in which case you should already be well aware of this!

With the `yubico-piv-tool` installed, we can run the following to generate the key, and save the public key to a pem formatted file:

`yubico-piv-tool -s 88 -a generate -o new_root_ca_pubkey.pem`

You can now create the root CA using this key, edit the config.json file to populate the following (this example is based on MacOS).  For testing you may wish to populate the AWS credentials.  For production, not.

```
{
    "Organisation": "PortSwigger",
    "Country": "UK",
    "CaName": "PortSwigger CA",
    "CaVersion": "2023",
    "OrgUnit": "SecEng",
    "City": "Knutsford",
    "County": "Cheshire",
    "SigningCert": "your_root_ca_cert.pem",
    "OCSPServer": "",
    "AwsRoleARN": "SOME_ARN_OF_ROLE_FROM_CLOUDFORMATION_OUTPUTS",
    "AwsMfaSerial": "SOME_AWS_ARN_OF_CREATED_MFA_TOKEN",
    "AwsDbTableName": "SOME_AWS_ARN_OF_CREATED_DYNAMODB_TABLE",
    "AwsRegion": "eu-west-1",
    "AwsAccessKey": "",
    "AwsSecretKey": "",
    "AwsTotpSecret": "",
    "P11Path": "/opt/homebrew/opt/yubico-piv-tool/lib/libykcs11.dylib",
    "P11TokenLabel": "",
    "P11Pin": "123456",
    "P11Slot": 0,
}
```

You should now be able to create an x509 certificate for the root CA, using something like:

Non Debug mode: 
`./certsquirt -ca -bootstrap -pubkey new_root_ca_pubkey.pem`

Debug mode :

`YKCS11_DBG=1 ./certsquirt -ca -bootstrap -pubkey new_root_ca_pubkey.pem -debug`

Assuming this all went well, you should see the last few lines say something like `INFO: Successfully wrote out pem cert to <SOMEFILE.PEM>`.  Edit the config.json file, changing the `SigningCert` entry to point to the new pem certificate file.

You may wish to continue this experiment, by creating a second key on the Yubikey.  For example, to create another key in slot 89, simply run something like:

`yubico-piv-tool -s 89 -a generate -o new_sub_ca_pubkey.pem`

You should now be able to create the SubCA using this new key, by running something like:

`./certsquirt -subca -subcaname "Yubikey Testing" -pubkey new_sub_ca_pubkey.pem`

This will result in another sub-ca pem file being written.  You can now swap out the `SigningCert` entry to point to this pem certificate file, resulting in any further signed certificates being signed by this subca/intermediate.

To continue the demo, create a new csr using openssl or similar.  To save you the effort of having to google this, something like the following will create a sub-standard csr (no SAN values), but will work for this example:

`openssl req -new -newkey rsa:2048 -nodes -out sdfasdf.csr -keyout sdfasdf.key -subj "/C=GB/ST=asdfsdfsadf/L=asdfasdf/O=asdfasdf/OU=sdfasdfasdf/CN=sdfasdf"`

With the new CSR, we should be able to issue our first certificate.  

If you run the following it will inspect the certificate request, and print out some details to the screen:

`./certsquirt -csr sdfasdf.csr`

and you should be able to sign it with:

`./certsquirt -csr sdfasdf.csr -sign`

You can then inspect the certificate using openssl or whatever you prefer, e.g.

`openssl x509 -in sdfasdf.pem -text -noout | less`

#
## AWS

It would be far superior from a rigour perspective if this was a new AWS account, with nothing in it other than secured root user access, using hardware MFA (yubikey, etc).

AWS KMS is very cheap - $1 per month per key.  In the below deployment , you will need 2 keys ($1/per key/per month), versus the cost of AWS Private CA ($0.75 per certificate) and, *mostly*, with all the security features that provides.

### Cloudformation.

In the cloudformation subdirectory is a [template](https://github.com/PortSwigger/certsquirt/blob/main/cloudformation/certsquirt.yaml) which will create the following:

* A CA root key in KMS (RSA 4096)
* A Sub CA key in KMS (RSA 4096)
* A DynamoDB Table for the service
* An IAM access role to be assumed via the app which has access to keys and DB
* A user which is allowed to assume the role when authentication uses MFA.

**Once executed, you need to find the user and then create** 
* an *access key*, and 
* a *software based* MFA token.  

The cloudformation script outputs the other variables you will need when creating the config.json file, to be copy/pasted into the config.json.

* *Tip*: You can hardcode these credentials into the config.json, in case you are testing as generating mfa codes can be annoying.  To do this, set the following variables within config.json:
    ```
    "AwsAccessKey": "AKIAXXXXXXXXXXXXXXXX",
    "AwsSecretKey": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "AwsTotpSecret": "BASE32SECRET",
* If these are set, we will then generate TOTP codes for you at runtime.  You may see errors when doing this though, as you can only use an MFA code precisely once every 30 seconds.


### Configuring AWS-KMS Mode Operations

You'll need to then install and configure the `aws-kms-pkcs11` layer - a link is at the bottom of this page.  

You will need to create a config.json for aws-kms-pkcs11. If you kept the defaults in the cloudformation the label will be correct, and you just need to replace the kms_key_id in the following config, which should be created in either /etc/aws-kms-pkcs11/config.json or $XDG_CONFIG_HOME/aws-kms-pkcs11/config.json (note that XDG_CONFIG_HOME=$HOME/.config by default).  

```
{
  "slots": [
    {
      "label": "CertSquirt-Root-CA-Key",
      "kms_key_id": "d52cbc45-eeb9-4dc5-bc53-487b20e8ae7e",
      "aws_region": "eu-west-1"
    }
  ]
}
```

Once you've configured everything... copy the root ca KMS key's public key to a file, and then you should now be able to create an x509 certificate for the root CA, using something like:

Non Debug mode: 

`./certsquirt -ca -bootstrap -pubkey new_root_ca_pubkey.pem`

Debug mode :

`AWS_KMS_PKCS11_DEBUG=1 ./certsquirt -ca -bootstrap -pubkey new_root_ca_pubkey.pem -debug`

Assuming this all went well, you should see the last few lines say something like `INFO: Successfully wrote out pem cert to <SOMEFILE.PEM>`.  Edit the config.json file, changing the `SigningCert` entry to point to the new pem certificate file.

Once this has worked, you should then copy the second sub-ca public key from the AWS KMS console to somewhere, and be able to run the following to sign the sub ca key, which you wil:

`./certsquirt -subca -subcaname "AWS SubCA Testing" -pubkey new_sub_ca_pubkey.pem`

Change the config file once again, to change the `SigningCert` entry to point to the new pem certificate file.  You should then be able to sign a CSR using something like:

`./certsquirt -csr sdfasdf.csr -sign`

You can then inspect the certificate using openssl or whatever you prefer, e.g.

`openssl x509 -in sdfasdf.pem -text -noout | less`

Once all this is working, create any more sub ca's you need, and once you've finished with this remove access to the root ca key by commenting out the [line](https://github.com/PortSwigger/certsquirt/blob/8c78d995856e4bbb3bb1a72d5c5dbf7561be2808/cloudformation/certsquirt.yaml#L165)  in the cloudformation, and running it again.

#
# Software Prerequisites
## AWS C++ SDK

You should follow the instructions at https://github.com/aws/aws-sdk-cpp in order to install the SDK.  Assuming that all went ok, move onto the next section.

## Jack of Most Trades - aws-kms-pkcs11

Next up, we will need to install https://github.com/JackOfMostTrades/aws-kms-pkcs11.  Again, follow the instructions on this page.

Pay close attention to https://github.com/JackOfMostTrades/aws-kms-pkcs11#configuration to ensure you have got things configured correctly, and that you can talk to your keys in KMS.

## Final Steps

With these in place, you should be good to go.  Checkout usage.txt which explains some of the first things you may wish to do...
