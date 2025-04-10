package main

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
)

type Signal struct {
	keyKind     string
	explanation string
}

type SAKey struct {
	serviceAccount string
	cert           *x509.Certificate
	signals        []Signal
	keyKind        string
}

func NewSAKey(serviceAccount string, cert *x509.Certificate) *SAKey {
	return &SAKey{
		serviceAccount: serviceAccount,
		cert:           cert,
		signals:        []Signal{},
	}
}

func (k *SAKey) CheckValidityPeriod() {
	validityWindow := k.cert.NotAfter.Sub(k.cert.NotBefore)

	if k.cert.NotAfter == defaultMaxAfter {
		k.signals = append(k.signals, Signal{
			keyKind:     GOOGLE_PROVIDED_USER_MANAGED,
			explanation: fmt.Sprintf("Certificate has a NotAfter date of %v", k.cert.NotAfter),
		})
	} else if validityWindow == legacyGoogleProvidedUserManagedValidity {
		k.signals = append(k.signals, Signal{
			keyKind:     GOOGLE_PROVIDED_USER_MANAGED,
			explanation: fmt.Sprintf("Certificate has a legacy 10y validity period of %v", validityWindow),
		})
	} else if validityWindow == googleProvidedSystemManagedValidityV1 {
		k.signals = append(k.signals, Signal{
			keyKind:     GOOGLE_PROVIDED_SYSTEM_MANAGED,
			explanation: fmt.Sprintf("Certificate has standard validity period of %v", validityWindow),
		})
	} else if slices.Contains(serviceAccountKeyExpiryHours, validityWindow) {
		k.signals = append(k.signals, Signal{
			keyKind:     GOOGLE_PROVIDED_USER_MANAGED,
			explanation: fmt.Sprintf("Certificate has a validity period in constraints/iam.serviceAccountKeyExpiryHours of %v", validityWindow),
		})
	} else if validityWindow > googleProvidedSystemManagedValidityV2Min && validityWindow < googleProvidedSystemManagedValidityV2Max {
		k.signals = append(k.signals, Signal{
			keyKind:     GOOGLE_PROVIDED_SYSTEM_MANAGED,
			explanation: fmt.Sprintf("Certificate has a validity period of %v which is between %v and %v", validityWindow, googleProvidedSystemManagedValidityV2Min, googleProvidedSystemManagedValidityV2Max),
		})
	} else {
		k.signals = append(k.signals, Signal{
			keyKind:     USER_PROVIDED_USER_MANAGED,
			explanation: fmt.Sprintf("Certificate does not have a standard GCP validity window: %v (%v to %v)", validityWindow, k.cert.NotBefore, k.cert.NotAfter),
		})
	}
}

func (k *SAKey) CheckExtensions() {
	if len(k.cert.ExtKeyUsage) != 1 || k.cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		k.signals = append(k.signals, Signal{
			keyKind:     USER_PROVIDED_USER_MANAGED,
			explanation: fmt.Sprintf("Certificate has unexpected ExtendedKeyUsage: %v", k.cert.ExtKeyUsage),
		})
	}

	if k.cert.KeyUsage != x509.KeyUsageDigitalSignature {
		k.signals = append(k.signals, Signal{
			keyKind:     USER_PROVIDED_USER_MANAGED,
			explanation: fmt.Sprintf("Certificate has unexpected KeyUsage: %v", k.cert.KeyUsage),
		})
	}
}

func (k *SAKey) checkNames() {
	expectedName := strings.Replace(k.serviceAccount, "@", ".", 1)
	// 64 is the maximum length for a CN
	var truncatedName string
	if len(expectedName) >= 64 {
		truncatedName = expectedName[:64]
	}

	checkName := func(t, v string) {
		if GAIA_ID.MatchString(v) {
			k.signals = append(k.signals, Signal{
				keyKind:     GOOGLE_PROVIDED_USER_MANAGED,
				explanation: fmt.Sprintf("%v %v is a GAIA_ID", t, v),
			})
		} else if v == expectedName {
			k.signals = append(k.signals, Signal{
				keyKind:     GOOGLE_PROVIDED_SYSTEM_MANAGED,
				explanation: fmt.Sprintf("%v %v matches expected name %v", t, v, expectedName),
			})
		} else if truncatedName != "" && v == truncatedName {
			k.signals = append(k.signals, Signal{
				keyKind:     GOOGLE_PROVIDED_SYSTEM_MANAGED,
				explanation: fmt.Sprintf("%v %v matches expected truncated name %v", t, v, truncatedName),
			})
		} else {
			k.signals = append(k.signals, Signal{
				keyKind:     USER_PROVIDED_USER_MANAGED,
				explanation: fmt.Sprintf("%v %v does not match any expected name %v", t, v, expectedName),
			})
		}
	}

	checkName("SubjectCN", k.cert.Subject.CommonName)
	checkName("IssuerCN", k.cert.Issuer.CommonName)
}

// Note: we don't emit positive signals for google provided keys here on purpose, only negative signals
// because a key using the same parameters as a google provided key is not necessarily a google provided key
func (k *SAKey) checkCrypto() {
	if k.cert.PublicKeyAlgorithm != x509.RSA {
		k.signals = append(k.signals, Signal{
			keyKind:     USER_PROVIDED_USER_MANAGED,
			explanation: fmt.Sprintf("Public key algorithm %v is not RSA", k.cert.PublicKeyAlgorithm),
		})
	}

	if k.cert.SignatureAlgorithm != x509.SHA1WithRSA {
		k.signals = append(k.signals, Signal{
			keyKind:     USER_PROVIDED_USER_MANAGED,
			explanation: fmt.Sprintf("Signature algorithm %v is not SHA1WithRSA", k.cert.SignatureAlgorithm),
		})
	}

	if k.cert.PublicKey.(*rsa.PublicKey).N.BitLen() == 1024 {
		k.signals = append(k.signals, Signal{
			keyKind:     GOOGLE_PROVIDED_USER_MANAGED,
			explanation: "Public key length is 1024",
		})
	} else if k.cert.PublicKey.(*rsa.PublicKey).N.BitLen() != 2048 {
		k.signals = append(k.signals, Signal{
			keyKind:     USER_PROVIDED_USER_MANAGED,
			explanation: fmt.Sprintf("Public key length %v is not 2048 or 1024", k.cert.PublicKey.(*rsa.PublicKey).N.BitLen()),
		})
	}
}

func (k *SAKey) check() {
	k.checkNames()
	k.checkCrypto()
	k.CheckValidityPeriod()
	k.CheckExtensions()
}

// Returns the keyOrigin and keyType of the key
// the precedence order is:
// 1. USER_PROVIDED+USER_MANAGED
// 2. GOOGLE_PROVIDED+USER_MANAGED
// 3. GOOGLE_PROVIDED+SYSTEM_MANAGED
// (note that GUSER_PROVIDED+SYSTEM_MANAGED is not possible)
func (k *SAKey) determineKeyKind() (res string) {
	k.check()

	// There should always be at least one signal from the validity period checks
	if len(k.signals) == 0 {
		panic("No signals found for key")
	}

	for _, signal := range k.signals {
		if res == "" {
			res = signal.keyKind
			continue
		}

		// If the current signal is higher in precedence than the current result, replace the result
		if slices.Index(keyKindPrecedence, signal.keyKind) < slices.Index(keyKindPrecedence, res) {
			res = signal.keyKind
		}
	}

	k.keyKind = res
	return
}

func (k *SAKey) dump(indent string, includeSignals bool) {
	fmt.Printf("%vKey ID: %v - likely %v\n", indent, k.cert.SerialNumber, k.keyKind)
	if includeSignals {
		for _, signal := range k.signals {
			fmt.Printf("%v  Signal for %v: %v\n", indent, signal.keyKind, signal.explanation)
		}
	}
}
