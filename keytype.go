package main

import "slices"

// These are "muxed key kinds", which are combinations of key origin and key type
// The google API separates these, but for the purposes of this program it's easier to combine them
// To minimize ambiguity between the two, we call them a "kind" instead of a type
const (
	GOOGLE_PROVIDED_SYSTEM_MANAGED = "GOOGLE_PROVIDED/SYSTEM_MANAGED"
	GOOGLE_PROVIDED_USER_MANAGED   = "GOOGLE_PROVIDED/USER_MANAGED"
	USER_PROVIDED_USER_MANAGED     = "USER_PROVIDED/USER_MANAGED"
)

// precendence order for key types based on the signals we see
// signals for higher ones take precedence over signals for lower ones
var keyKindPrecedence = []string{
	USER_PROVIDED_USER_MANAGED,
	GOOGLE_PROVIDED_USER_MANAGED,
	GOOGLE_PROVIDED_SYSTEM_MANAGED,
}

func keyTypeAndOriginToMuxedKeyKind(keyType string, keyOrigin string) string {
	res := keyOrigin + "/" + keyType
	if slices.Index(keyKindPrecedence, res) == -1 {
		panic("Invalid key type and origin combination: " + res)
	}
	return res
}
