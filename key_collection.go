package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"sync"

	"golang.org/x/sync/semaphore"
	"golang.org/x/time/rate"
)

type KeyCollection struct {
	serviceAccountIDs []string
	observedKeys      []ServiceAccountCerts
	groundTruthKeys   []ServiceAccountKeys
	badSAsLock        sync.Mutex
	badSAs            []string
}

func NewKeyCollection(serviceAccountIDs []string) *KeyCollection {
	return &KeyCollection{
		serviceAccountIDs: serviceAccountIDs,
	}
}

func (k *KeyCollection) FetchKeys(groundTruth bool, quotaProject string) error {
	err := k.FetchObservedKeys()
	if err != nil {
		return err
	}
	if groundTruth {
		err := k.FetchGroundTruthKeys()
		if err != nil {
			return err
		}
	}
	return nil
}

func (k *KeyCollection) FetchGroundTruthKeys() error {
	limiter := rate.NewLimiter(rate.Limit(IAMReadRequestsPerMinutePerProjectMax/60.0), 1)

	k.groundTruthKeys = make([]ServiceAccountKeys, len(k.serviceAccountIDs))

	iam := iamService()

	res, err := parllelMap(k.serviceAccountIDs, func(sa string) (ServiceAccountKeys, error) {
		if k.isBadSA(sa) {
			return nil, nil
		}
		if err := limiter.Wait(context.Background()); err != nil {
			return nil, err
		}
		return getServiceAccountKeys(context.Background(), iam, sa)
	})
	if err != nil {
		return fmt.Errorf("error getting keys from GCP API: %v", err)
	}
	k.groundTruthKeys = res
	return nil
}

func (k *KeyCollection) FetchObservedKeys() error {
	inflight := semaphore.NewWeighted(MaxInflightX509)

	k.observedKeys = make([]ServiceAccountCerts, len(k.serviceAccountIDs))

	observedKeys, err := parllelMap(k.serviceAccountIDs, func(sa string) (ServiceAccountCerts, error) {
		if err := inflight.Acquire(context.Background(), 1); err != nil {
			return nil, err
		}
		defer inflight.Release(1)
		res, err := getServiceAccountKeyCerts(sa)
		if err != nil {
			fmt.Printf("Warning: error getting keys for service account %v: %v\n", sa, err)
			k.addBadSA(sa)
			return nil, nil
		}
		return res, nil
	})
	if err != nil {
		return fmt.Errorf("error getting keys from GCP API: %v", err)
	}
	k.observedKeys = observedKeys
	return nil
}

func (k *KeyCollection) isBadSA(sa string) bool {
	k.badSAsLock.Lock()
	defer k.badSAsLock.Unlock()
	return slices.Contains(k.badSAs, sa)
}

func (k *KeyCollection) addBadSA(sa string) {
	k.badSAsLock.Lock()
	defer k.badSAsLock.Unlock()
	k.badSAs = append(k.badSAs, sa)
}

func (k *KeyCollection) WritePublicKeysToDir(s string) error {
	err := os.MkdirAll(s, 0755)
	if err != nil {
		return fmt.Errorf("error creating directory %v: %v", s, err)
	}

	for i, sa := range k.serviceAccountIDs {
		if k.isBadSA(sa) {
			continue
		}
		for keyID, cert := range k.observedKeys[i] {
			fname := fmt.Sprintf("%v/%v_%v.pem", s, sa, keyID)
			f, err := os.Create(fname)
			if err != nil {
				return fmt.Errorf("error creating file %v: %v", fname, err)
			}
			err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			if err != nil {
				return fmt.Errorf("error encoding PEM block: %v", err)
			}
			err = f.Close()
			if err != nil {
				return fmt.Errorf("error closing file %v: %v", fname, err)
			}
		}
	}

	return nil
}
