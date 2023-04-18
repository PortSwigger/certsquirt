package main

import (
	"crypto/rsa"
	"errors"
	"log"

	"github.com/ThalesIgnite/crypto11"
)

func initPkcs11(pubkey *rsa.PublicKey) (signer crypto11.Signer, err error) {
	if flDebug {
		log.Printf("DEBUG: init called with pubkey of type %T", pubkey)
	}
	// depending on AWS-KMS or YubiKey we need to pass these in differently...
	// var p11Config crypto11.Config

	// if config.UseKms {
	// 	if flDebug {
	// 		log.Printf("DEBUG: Attempting to configure pkcs11 with AWS KMS")
	// 	}
	// 	p11Config = crypto11.Config{
	// 		// if you're looking here, look here: https://pkg.go.dev/github.com/ThalesIgnite/crypto11#Config
	// 		Path:       config.Path,
	// 		TokenLabel: config.TokenLabel,
	// 	}
	// } else if config.UseYubi {
	// 	if flDebug {
	// 		log.Printf("DEBUG: Attempting to configure pkcs11 with Yubikey")
	// 	}
	p11Config := crypto11.Config{
		Path: config.Path,
		Pin:  config.Pin,
		//SlotNumber: &config.SlotNumber,
		TokenLabel: config.TokenLabel,
	}

	if flDebug {
		log.Printf("DEBUG: P11Config is %#v", p11Config)
	}
	ctx, err := crypto11.Configure(&p11Config)
	if err != nil {
		return signer, err
	}
	signers, err := ctx.FindAllKeyPairs()
	if err != nil {
		return signer, err
	}
	if flDebug {
		log.Printf("Signers are: %#v", signers)
	}
	for x, y := range signers {
		if flDebug {
			log.Printf("Signer is a %T %#v", y.Public(), y)
		}
		switch y.Public().(type) {
		case *rsa.PublicKey:
			//var signingkey *rsa.PublicKey = y.Public().(*rsa.PublicKey)
			if pubkey.Equal(y.Public()) {
				//if signingkey.Equal(pubkey.(rsa.PublicKey)) {
				return signers[x], nil
			} else {
				log.Printf("INFO: public key mismatch, checking next key")
			}
		default:
			// do nowt.
		}
	}
	return signer, errors.New("something weird happened.  please file an issue at https://github.com/PortSwigger/certsquirt/issues")
}
