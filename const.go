package main

import (
	"regexp"
	"time"
)

// This doesn't seem to be documented anywhere, but GCP internal SA keys are valid for exactly 396h15m
const googleProvidedSystemManagedValidityV1 = time.Hour*396 + time.Minute*15

// Newer keys seem to generate a key that has a random validity periiod between 2 years and 2 years and one month
var googleProvidedSystemManagedValidityV2Min = time.Hour * 24 * 365 * 2
var googleProvidedSystemManagedValidityV2Max = time.Hour * 24 * (365*2 + 31)

// This is the default max value for a certificate that is google provided user managed
var defaultMaxAfter = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)

// For old SA Keys, they seem to have have this as a validity period
var legacyGoogleProvidedUserManagedValidity = 87600 * time.Hour

// available validity periods for GOOGLE_PROVIDED+USER_MANAGED keys
// https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts#limit_key_expiry
var serviceAccountKeyExpiryHours = []time.Duration{
	time.Hour * 1,
	time.Hour * 8,
	time.Hour * 24,
	time.Hour * 168,
	time.Hour * 336,
	time.Hour * 720,
	time.Hour * 1440,
	time.Hour * 2160,
}

var GAIA_ID = regexp.MustCompile("^1[0-9]{20}$")

var IAMReadRequestsPerMinutePerProjectMax = 5500 // really 6000, but leave some buffer
const MaxInflightX509 = 64                       // max requests to make at once for the x509 certs
