package main

import (
	"context"
	"fmt"
	"strings"

	asset "cloud.google.com/go/asset/apiv1"
	"cloud.google.com/go/asset/apiv1/assetpb"
	"google.golang.org/api/iam/v1"
)

type ServiceAccountKeys map[string]*iam.ServiceAccountKey

func getServiceAccountKeys(ctx context.Context, iamService *iam.Service, sa string) (ServiceAccountKeys, error) {
	keys, err := iamService.Projects.ServiceAccounts.Keys.List("projects/-/serviceAccounts/" + sa).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	res := map[string]*iam.ServiceAccountKey{}
	num_internal := 0
	for _, key := range keys.Keys {
		id := strings.SplitAfter(key.Name, "keys/")[1]
		res[id] = key
		if key.KeyOrigin == "GOOGLE_PROVIDED" && key.KeyType == "SYSTEM_MANAGED" {
			num_internal++
		}
	}

	if num_internal > 3 {
		fmt.Printf("Warning: More than 3 (%v) internal keys found for %v. Please file a bug report.", num_internal, sa)
	}

	return res, nil
}

// Note: we skip any service accounts that are disabled
func getServiceAccountIDsInProject(ctx context.Context, iamService *iam.Service, project string) ([]string, error) {
	var serviceAccountIDs []string

	err := iamService.Projects.ServiceAccounts.List("projects/"+project).Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
		for _, serviceAccount := range page.Accounts {
			if serviceAccount.Disabled {
				continue
			}
			serviceAccountIDs = append(serviceAccountIDs, serviceAccount.Email)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return serviceAccountIDs, nil
}

func getServiceAccountIDsViaAssetInventory(ctx context.Context, c *asset.Client, scope string) ([]string, error) {
	var serviceAccountIDs []string
	for res, err := range c.SearchAllResources(ctx, &assetpb.SearchAllResourcesRequest{
		Scope:      scope,
		AssetTypes: []string{"iam.googleapis.com/ServiceAccount"},
		Query:      "state=ENABLED",
		PageSize:   500, // max,
	}).All() {
		if err != nil {
			return nil, err
		}

		serviceAccountID := res.AdditionalAttributes.Fields["email"].GetStringValue()
		serviceAccountIDs = append(serviceAccountIDs, serviceAccountID)
	}

	return serviceAccountIDs, nil
}
