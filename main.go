package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"sync"

	asset "cloud.google.com/go/asset/apiv1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

var groundTruth = flag.Bool("ground-truth", false, "If specified, will check against the GCP API for the ground truth")
var verbose = flag.Bool("verbose", false, "If specified, will print verbose output")

var project = flag.String("project", "", "The project to use for the GCP API, to list all service accounts (useful with -ground-truth)")
var scope = flag.String("scope", "", "Use the cloud asset API to get SAs. Can be any cloud asset supported scope like organizations/{ORGANIZATION_NUMBER} or folders/{FOLDER_NUMBER} (useful with -ground-truth)")
var inFile = flag.String("in", "", "Input file to read service accounts from, one per line")

var outDir = flag.String("out-dir", "", "Output directory to write PEM x509 certificates to")
var quotaProject = flag.String("quota-project", "", "Quota project to use for the GCP API. This is required if you are using a service account that is not in the same project as the service account you are trying to list keys for. This is also required if you are using the cloud asset API with --scope.")

// output modes
const (
	OUTPUT_NORMAL       = "normal"
	OUTPUT_VERBOSE      = "verbose"
	OUTPUT_GROUND_TRUTH = "ground-truth"
)

// return false if more than one of the flags is true
func checkMultualExcluveFlags(flags []bool) bool {
	count := 0
	for _, f := range flags {
		if f {
			count++
		}
	}
	return count <= 1
}

func decideOutputMode() (string, error) {
	if !checkMultualExcluveFlags([]bool{*groundTruth, *verbose}) {
		return "", fmt.Errorf("must specify one of --ground-truth, or --verbose")
	}
	if *groundTruth {
		return OUTPUT_GROUND_TRUTH, nil
	}
	if *verbose {
		return OUTPUT_VERBOSE, nil
	}
	return OUTPUT_NORMAL, nil
}

func gcpClientOptions() []option.ClientOption {
	var options []option.ClientOption
	if *quotaProject != "" {
		options = append(options, option.WithQuotaProject(*quotaProject))
	}
	return options
}

var iamService = sync.OnceValue(func() *iam.Service {
	iamService, err := iam.NewService(context.Background(), gcpClientOptions()...)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return iamService
})

func getTargetServiceAccounts() ([]string, error) {
	if !checkMultualExcluveFlags([]bool{*inFile != "", flag.NArg() > 0, *scope != "", *project != ""}) {
		return nil, fmt.Errorf("must specify one of --scope, --project, --in, or service accounts as arguments")
	}

	if *scope != "" {
		c, err := asset.NewClient(context.Background(), gcpClientOptions()...)
		if err != nil {
			return nil, err
		}
		return getServiceAccountIDsViaAssetInventory(context.Background(), c, *scope)
	} else if *project != "" {
		return getServiceAccountIDsInProject(context.Background(), iamService(), *project)
	} else if *inFile != "" {
		return getServiceAccountsFromFile(*inFile)
	} else {
		return flag.Args(), nil
	}
}

func getServiceAccountsFromFile(s string) ([]string, error) {
	f, err := os.Open(s)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var res []string
	for scanner.Scan() {
		res = append(res, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func main() {
	flag.Parse()

	serviceAccountIDs, err := getTargetServiceAccounts()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if len(serviceAccountIDs) == 0 {
		fmt.Println("No service accounts specified. Please specify one or more service accounts or use --project or --scope.")
		os.Exit(1)
	}

	outputMode, err := decideOutputMode()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Analyzing %d service accounts\n", len(serviceAccountIDs))

	keyCollection := NewKeyCollection(serviceAccountIDs)
	err = keyCollection.FetchKeys(*groundTruth, *quotaProject)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if *outDir != "" {
		err = keyCollection.WritePublicKeysToDir(*outDir)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	good := 0
	bad := 0

	for i, serviceAccountID := range serviceAccountIDs {
		if keyCollection.isBadSA(serviceAccountID) {
			continue
		}
		printedName := false
		if outputMode == OUTPUT_VERBOSE {
			fmt.Printf("Service Account: %v\n", serviceAccountID)
		}

		hasBadKeys := false
		for keyId, cert := range keyCollection.observedKeys[i] {
			key := NewSAKey(serviceAccountID, cert)
			keyKind := key.determineKeyKind()
			switch outputMode {
			case OUTPUT_NORMAL:
				if keyKind != GOOGLE_PROVIDED_SYSTEM_MANAGED {
					if !printedName {
						fmt.Printf("Service Account: %v\n", serviceAccountID)
						printedName = true
					}
					key.dump("  ", true)
					hasBadKeys = true
				}
			case OUTPUT_VERBOSE:
				key.dump("  ", true)
				if keyKind != GOOGLE_PROVIDED_SYSTEM_MANAGED {
					hasBadKeys = true
				}
			case OUTPUT_GROUND_TRUTH:
				realKey := keyCollection.groundTruthKeys[i][keyId]
				realKeyKind := keyTypeAndOriginToMuxedKeyKind(realKey.KeyType, realKey.KeyOrigin)
				if realKeyKind != keyKind {
					hasBadKeys = true
					if !printedName {
						fmt.Printf("Service Account: %v\n", serviceAccountID)
						printedName = true
					}
					fmt.Printf("  Key ID: %v - expected %v, got %v\n", key.cert.SerialNumber, realKeyKind, keyKind)
					key.dump("    ", true)
				}
			}
		}
		if hasBadKeys {
			bad++
		} else {
			good++
		}
	}

	fmt.Printf("Good SAs: %d, Bad SAs: %d\n", good, bad)

	if bad > 0 {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
