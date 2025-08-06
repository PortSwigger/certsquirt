package main

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/ThalesGroup/crypto11"
)

func initPkcs11(pubkey *rsa.PublicKey) (signer crypto11.Signer, err error) {
	logger := GetLogger()
	if flDebug {
		logger.Debug("PKCS11 initialization", "pubkey_type", fmt.Sprintf("%T", pubkey))
	}
	// depending on the pkcs11 provider we need to pass these in differently.
	// For KMS and some others , we need to find the key via the Token Label,
	// but the YubiKey and others, we need to locate the token via the slot.
	//
	// crypto11.Config
	var p11Config crypto11.Config
	if flDebug {
		logger.Debug("PKCS11 provider configuration", 
			"library_path", config.Path,
			"pin_configured", config.Pin != "",
			"token_label", config.TokenLabel,
			"slot_number", config.SlotNumber)
	}
	if config.TokenLabel != "" {
		p11Config = crypto11.Config{
			Path: config.Path,
			Pin:  config.Pin,
			//SlotNumber: &config.SlotNumber,
			TokenLabel: config.TokenLabel,
		}
	} else {
		p11Config = crypto11.Config{
			Path:       config.Path,
			Pin:        config.Pin,
			SlotNumber: &config.SlotNumber,
			//TokenLabel: config.TokenLabel,
		}
	}

	if flDebug {
		logger.Debug("PKCS11 configuration created", "config", p11Config)
	}
	ctx, err := crypto11.Configure(&p11Config)
	if err != nil {
		logger.Error("PKCS11 context configuration failed", "error", err)
		return signer, err
	}
	if flDebug {
		logger.Debug("PKCS11 context created successfully")
	}
	signers, err := ctx.FindAllKeyPairs()
	if err != nil {
		logger.Error("Failed to find key pairs in PKCS11 context", "error", err)
		return signer, err
	}
	if flDebug {
		logger.Debug("Found PKCS11 key pairs", "count", len(signers))
	}
	for x, y := range signers {
		if flDebug {
			logger.Debug("Examining signer", 
				"index", x,
				"public_key_type", fmt.Sprintf("%T", y.Public()))
		}
		switch y.Public().(type) {
		case *rsa.PublicKey:
			if pubkey.Equal(y.Public()) {
				logger.Info("Found matching PKCS11 key pair", "index", x)
				AuditEvent("pkcs11_key_found", true,
					"key_index", x,
					"key_type", "RSA")
				return signers[x], nil
			} else {
				if flDebug {
					logger.Debug("Public key mismatch, checking next key", "index", x)
				}
			}
		default:
			if flDebug {
				logger.Debug("Skipping non-RSA key", 
					"index", x, 
					"key_type", fmt.Sprintf("%T", y.Public()))
			}
		}
	}
	logger.Error("No matching PKCS11 key pair found", 
		"searched_keys", len(signers),
		"suggestion", "verify the public key file matches a key in the PKCS11 provider")
	AuditEvent("pkcs11_key_found", false,
		"searched_keys", len(signers),
		"reason", "no_matching_key")
	return signer, errors.New("no matching key pair found in PKCS11 provider")
}
