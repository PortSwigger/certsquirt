# A golang PKI in less than 1000 lines of code.

# Installation

This is a little complex.  

Apologies.

While there are native API's to talk to KMS directly, one of the goals of this project was to make things configurable, so that you are not tied to a singly crypto provider.  To that end, we chose to use [pkcs11](https://en.wikipedia.org/wiki/PKCS_11) as a crypto provider.  This means you should theoretically be able to talk to ['real world' HSM's](https://github.com/ThalesIgnite/crypto11#testing-with-thales-luna-hsm), [AWS CloudHSM](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html), [YubiKeys](https://developers.yubico.com/yubico-piv-tool/YKCS11/) , et al.  

This effectively gives you an excellent starting point to expand your crypto world as you progress - you should be able to start with AWS KMS and then as requirements dictate, migrate upwards to more robust crypto providers.  You could mix and match, for example the root in KMS and a YubiKey for issuing certificates, or a Yubikey for root and KMS for the subca issuing, or just 2 Yubikeys.

However, this extensibility does come at a price - a little complexity to get started.  The rest of this guide covers using AWS KMS, but please do try others and raise issues you find with other pkcs11 providers.

To get you up and running, we will use AWS KMS as it's insanely cheap - $1 per month per key.  In this model, you will need 2 keys, versus the cost of AWS Private CA ($0.75 per certificate) and, *mostly*, with all the security features that provides.

#
## AWS

It would be far superior from a rigour perspective if this was a new AWS account, with nothing in it other than secured root user access, using hardware MFA (yubikey, etc).

### Cloudformation.
In Progress.  Watch this space.



### AWS IAM Role

These permission policies attached to the role work, but could be scoped tighter:

* AmazonDynamoDBFullAccess
* AWSKeyManagementServicePowerUser

For 'Trust Relationships', ensure that MFA is forced to be used when our IAM user assumes the role:

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        }
    ]
}
```

Next, we need a user.

### AWS IAM User

Create a user, with the following as a custom permission policy.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{ROLE_CREATED_ABOVE}"
        }
    ]
}
```

This effectively creates a user with absolutely no permissions, aside from being able to assume the role above using MFA/TOTP based authentication.  

With this user created, head over to 'Security Credentials' on the user info page and generate some access keys to be used to authenticate to the API's, and 'Assign MFA Device', following the instructions in the page.

* *Tip*: You can hardcode these credentials into the binary, in case you are testing as generating mfa codes can be annoying.  To do this, set the following variables within awsauth.go:
    ```
    var (
        awsAccessKey = ""
        awsSecretKey = ""
        awsTotpKey   = ""
    )
* If these are set, we will then generate TOTP codes for you at runtime.  You may see errors when doing this though, as you can only use an MFA code precisely once every 30 seconds.

### AWS KMS Keys

At this point, with the user and role and access credentials in place, we can generate the KMS keys.

* You will want to create an 'Asymmetric' Key, with usage 'Sign and Verify', of type RSA_4096
* The Key Administrator should not be the user above, but a different user or simply left blank.
* The Key Users should be set to the role you created above.
* Alternatively you can delegate access usage to this key to another AWS account.

#
# Software Prerequisites
## AWS C++ SDK

You should follow the instructions at https://github.com/aws/aws-sdk-cpp in order to install the SDK.  Assuming that all went ok, move onto the next section.

## Jack of Most Trades - aws-kms-pkcs11

Next up, we will need to install https://github.com/JackOfMostTrades/aws-kms-pkcs11.  Again, follow the instructions on this page.

Pay close attention to https://github.com/JackOfMostTrades/aws-kms-pkcs11#configuration to ensure you have got things configured correctly, and that you can talk to your keys in KMS.

## Final Steps

With these in place, you should be good to go.  Checkout usage.txt which explains some of the first things you may wish to do...
