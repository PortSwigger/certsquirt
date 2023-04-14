package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/ThalesIgnite/crypto11"
)

func testPkcs11() (ctx *crypto11.Context, err error) {
	// depending on AWS-KMS or YubiKey we need to pass these in differently...
	var p11Config crypto11.Config

	if config.UseKms {
		if flDebug {
			log.Printf("DEBUG: Attempting to configure pkcs11 with AWS KMS")
		}
		p11Config = crypto11.Config{
			// if you're looking here, look here: https://pkg.go.dev/github.com/ThalesIgnite/crypto11#Config
			Path:       config.Path,
			TokenLabel: config.TokenLabel,
		}
	} else if config.UseYubi {
		if flDebug {
			log.Printf("DEBUG: Attempting to configure pkcs11 with Yubikey")
		}
		p11Config = crypto11.Config{
			Path:       config.Path,
			Pin:        config.Pin,
			SlotNumber: &config.SlotNumber,
		}
	}
	if flDebug {
		log.Printf("DEBUG: P11Config is %#v", p11Config)
	}
	ctx, err = crypto11.Configure(&p11Config)
	if err != nil {
		return ctx, err
	}
	if flDebug {
		log.Printf("DEBUG: Crypto11 context is %#v", ctx)
	}
	signers, err := ctx.FindAllKeyPairs()
	if err != nil {
		return ctx, err
	}
	// test we can use to sign and verify
	data := []byte("mary had a little lamb")
	h := sha256.New()
	_, err = h.Write(data)
	if err != nil {
		fmt.Println(err)
		return ctx, err
	}
	hash := h.Sum([]byte{})
	// here we diverge - on AWS we use the first signer, on the yubikey the second
	var signer crypto11.Signer
	if config.UseKms {
		signer = signers[0]
	} else if config.UseYubi {
		signer = signers[1]
	}
	// so this is a tricky one - KMS will let us keep our connection to do multiple operations,
	// so we can keep spending out ticket to ride... But the Yubikey forces a relogin after each
	// operation, so we can't do the following test there (as we'd need to loop around later and
	// grab a new context.  Assume it 'simply will work' when we need it to.
	if config.UseKms {
		sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
		if err != nil {
			fmt.Println(err)
			return ctx, err
		}
		if flDebug {
			log.Printf("DEBUG: Success signing test data using the pkcs11 provider")
		}
		err = rsa.VerifyPKCS1v15(signer.Public().(crypto.PublicKey).(*rsa.PublicKey), crypto.SHA256, hash, sig)
		if err != nil {
			fmt.Println(err)
			return ctx, err
		}
		if flDebug {
			log.Printf("DEBUG: Success verifying test data using the public key")
		}
	}
	return ctx, nil
}
