# A golang PKI in less than 1000 lines of code.

# Caveats

Although not an issue with this solution per se, the `aws-kms-pkcs11` provider does not build easily on MacOS.  You are advised to use a Linux machine/VM to run this solution if you wish to use KMS.  If you are using Yubikeys, this restriction doesn't apply.

# Installation

While there are native API's to talk to KMS directly, one of the goals of this project was to make things configurable, so that you are not tied to a singly crypto provider.  To that end, we chose to use [pkcs11](https://en.wikipedia.org/wiki/PKCS_11) as a crypto provider.  This means you should theoretically be able to talk to ['real world' HSM's](https://github.com/ThalesIgnite/crypto11#testing-with-thales-luna-hsm), [AWS CloudHSM](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html), [YubiKeys](https://developers.yubico.com/yubico-piv-tool/YKCS11/) , et al.  

This effectively gives you an excellent starting point to expand your crypto world as you progress - you should be able to start with AWS KMS and then as requirements dictate, migrate upwards to more robust crypto providers.  You could mix and match, for example the root in KMS and a YubiKey for issuing certificates, or a Yubikey for root and KMS for the subca issuing, or just 2 Yubikeys.

However, this extensibility does come at a price - a little complexity to get started.  The rest of this guide covers using AWS KMS, but please do try others and raise issues you find with other pkcs11 providers.

To get you up and running, we will use AWS KMS as it's insanely cheap - $1 per month per key.  In this model, you will need 2 keys, versus the cost of AWS Private CA ($0.75 per certificate) and, *mostly*, with all the security features that provides.

## AWS

It would be far superior from a rigour perspective if this was a new AWS account, with nothing in it other than secured root user access, using hardware MFA (yubikey, etc).

### Cloudformation.

In the cloudformation subdirectory is a template which will create the following:

* A CA root key in KMS (RSA 4096)
* A Sub CA key in KMS (RSA 4096)
* A DynamoDB Table for the service
* An IAM access role to be assumed via the app which has access to keys and DB
* A user which is allowed to assume the role when authentication uses MFA.

Once executed, you need to find the user and create an access key, and a software based MFA token.  The script outputs the other variables you should need when creating the config.json file, to be copy/pasta to it.

* *Tip*: You can hardcode these credentials into the config.json, in case you are testing as generating mfa codes can be annoying.  To do this, set the following variables within config.json:
    ```
    "AwsAccessKey": "AKIAXXXXXXXXXXXXXXXX",
    "AwsSecretKey": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "AwsTotpSecret": "BASE32SECRET",
* If these are set, we will then generate TOTP codes for you at runtime.  You may see errors when doing this though, as you can only use an MFA code precisely once every 30 seconds.

#
# Software Prerequisites
## AWS C++ SDK

You should follow the instructions at https://github.com/aws/aws-sdk-cpp in order to install the SDK.  Assuming that all went ok, move onto the next section.

## Jack of Most Trades - aws-kms-pkcs11

Next up, we will need to install https://github.com/JackOfMostTrades/aws-kms-pkcs11.  Again, follow the instructions on this page.

Pay close attention to https://github.com/JackOfMostTrades/aws-kms-pkcs11#configuration to ensure you have got things configured correctly, and that you can talk to your keys in KMS.

## Final Steps

With these in place, you should be good to go.  Checkout usage.txt which explains some of the first things you may wish to do...
