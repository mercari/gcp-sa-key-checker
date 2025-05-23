# Third Party GCP Service Account Key Checker

This program implements a simple security checker for GCP Service Account Keys for any GCP Service Account using the [public x509 certificate endpoint](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys#confidential-information).

It is useful for auditing if GCP Service Accounts used by third party SaaS services are following [best pratices](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys) before you grant them access to your environment.

## Background

All Google Cloud Service Accounts have service account keys associated with them which they use for signing JWTs which can be used as idtokens or [exchanged for access tokens](https://developers.google.com/identity/protocols/oauth2/service-account#httprest). These are almost always 2048-bit RSA keys and are a foundational component of the GCP security model.

These keys have attributes `keyOrigin` and `keyType`, which can be:

- `keyOrigin`
  - `GOOGLE_PROVIDED` - key material was generated by Google
  - `USER_PROVIDED` - generated by the user
- `keyType`
  - `SYSTEM_MANAGED` - key material is managed by GCP
  - `USER_MANAGED` - key material is managed by the user

These can be in the following combinations:

- `GOOGLE_PROVIDED`/`SYSTEM_MANAGED` these are the cloud platform internal SAs that are attached to every Service Account. These keys are used by the methods in the [Service Account Credentials REST API](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts) like [`SignJWT`](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt).
- `GOOGLE_PROVIDED`/`SYSTEM_MANAGED` these are created by the [`projects.serviceAccounts.keys.create` API](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/create) and then downloaded to get a "Service Account Key JSON".
- `USER_PROVIDED`/`USER_MANAGED` these are created by the user and the certificate portion is uploaded using [`projects.serviceAccounts.keys.upload` API](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/upload). Google Cloud never has access to these private keys.

Note that `USER_PROVIDED`/`SYSTEM_MANAGED` doesn't exist because there's no way to import private key material into the cloud.

According to [Best practices for managing service account keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys) it is prefered to not have *any* `USER_MANAGED` keys.

GCP does not directly make the information about what types of keys are attached to a service account public, however, it does provide several endpoints (documented [here](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys#confidential-information) and [here](https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/signJwt)) to see the public portions of the keys, to be used for verifying signatures.

This tool takes the certificates from the public x509 endpoint, and uses heuristics to determine the key origin and type for each key.

## Usage

Clone this repository and ensure you have golang installed.

If you plan to use features requiring GCP authentication, ensure you run `gcloud auth login --update-adc`.

You can run the tool with `go run ./... [args]` (or `go build` and then `./gcp-sa-key-checker [args]`).

The list of Service Account emails to process can be provided in four different ways:

- On the command line as individual positional arguments
- with the `--in FILE` flag, pointing to a text file with one service account email on each line
- with the `--project PROJECTID` flag, which will list all Service Accounts in the project using the [`projects.serviceAccounts.list` API](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/list)
- with the `--scope SCOPE` flag, which will list all active service accounts using the [`searchAllResources` API](https://cloud.google.com/asset-inventory/docs/reference/rest/v1/TopLevel/searchAllResources). Supported scopes are:
  - `projects/{PROJECT_ID}` or `projects/{PROJECT_NUMBER}` (redundant with `--project` flag, but requires different permissions)
  - `folders/{FOLDER_NUMBER}`
  - `organizations/{ORGANIZATION_NUMBER}`

The tool can be run in two different modes:

- Normal: Default mode, only list keys that are likely not `GOOGLE_PROVIDED`/`SYSTEM_MANAGED`
- Verbose: enabled with `--verbose`, it will output all the information about all keys seen. This could be useful for diffing and monitoring but is mostly for debugging.
- Ground Truth: enabled with `--ground-truth`, it will use ADCs to pull the real status of the keys [from the IAM API](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys/list), and then compare that with the predicted `keyOrigin`/`keyType` from the public information, then it will report any descrepencies. This is useful for verifying the correctness of the heuristics.

Additional flags:

- `--out-dir DIR` - will write the PEM encoded x509 certificates for all scanned SAs to the output directory
- `--quota-project PROJECT_ID` - will use the specified project for quota/billing purposes. Only really relevant for the `--ground-truth` which issues many IAM read calls.

## How it Works

The certificate for each SA key is downloaded using the `https://www.googleapis.com/service_accounts/v1/metadata/x509/ACCOUNT_EMAIL` endpoint. Checks are run to gather "Signals" which are a guess towards a specific keyOrigin+keyType combination, and an explanation. The following checks are run, each of which were determined experimentally:

- Validity period (`NotBefore`, `NotAfter`)
  - `16d12h15m` -> `GOOGLE_PROVIDED`/`SYSTEM_MANAGED`
    - ["two weeks"](https://github.com/googleapis/google-api-python-client/blob/84c3332759030a1b57a56bb3bd74a58b484253a0/docs/dyn/iam_v1.projects.serviceAccounts.keys.html#L237C475-L237C484) seems to be a hardcoded value
  - `3650d` (~10 years) -> `GOOGLE_PROVIDED`/`USER_MANAGED`
    - legacy user-created SA keys [had a 10 year validity](https://cloud.google.com/blog/products/containers-kubernetes/introducing-workload-identity-better-authentication-for-your-gke-applications#:~:text=but%20service%20account%20keys%20only%20expire%20every%2010%20years)
  - Valid between `730d` (~2 years) and `761d` (~2 years + 1 month) -> `GOOGLE_PROVIDED`/`SYSTEM_MANAGED`
    - This does not seem to be documented but was confirmed experimentally. Seems to have started rollout around February 2025
  - `NotAfter` date of `9999-12-31 23:59:59 +0000 UTC` -> `GOOGLE_PROVIDED`/`SYSTEM_MANAGED`
    - SA keys generated after around May 2021 seem to not expire at all
  - Any period in the [`iam.serviceAccountKeyExpiryHours` org constraint](https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts#limit_key_expiry) -> `GOOGLE_PROVIDED`/`USER_MANAGED`
  - Any other period can not be generated by Google Cloud, so must be `USER_PROVIDED`/`USER_MANAGED`
- Names (`Subject` and `Issuer`)
  - GAIA IDs -> `GOOGLE_PROVIDED`/`USER_MANAGED`
    - Experimentally determined user-generated keys always have GAIA IDs in these fields.
  - service account email or email truncated to 64 bytes -> `GOOGLE_PROVIDED`/`GOOGLE_MANAGED`
    - It is unclear when this truncation occurs, and seems to not be documented.
  - Anything else cannot be generated by GCP -> `USER_PROVIDED`/`USER_MANAGED`
- Crypto settings:
  - 1024 bit `SHA1WithRSA` -> `GOOGLE_PROVIDED`/`USER_MANAGED`
    - not sure why anyone would do this, but [the API allows it](https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys#ServiceAccountKeyAlgorithm)
  - anything else other than 2024 bit `SHA1WithRSA` -> `USER_PROVIDED`/`USER_MANAGED`
- The extensions (key usage, etc) are also checked because these are very consistent from GCP, so if they differ they key must have been `USER_PROVIDED`.

Finally, the signals are compiled, and ordered by precedence. The highest precedence finding wins. The prececdence order is `USER_PROVIDED/USER_MANAGED`, `GOOGLE_PROVIDED/USER_MANAGED` and finally `GOOGLE_PROVIDED/GOOGLE_MANAGED`.

## Findings

This was run with `--ground-truth` across the main Mercari GCP organization which has existed for over 10 years and contains >20k service accounts, including some that have user-generated or user-managed keys. There were no disparities between the heuristic detection code in this script and the ground truth from the API.

Additionally, we pulled data from [Wiz](https://app.wiz.io/) for external service accounts that are connected to our environment using the following advanced query:

```json
{
  "select": true,
  "type": [
    "SERVICE_ACCOUNT"
  ],
  "where": {
    "_partial": {
      "EQUALS": true
    },
    "externalId": {
      "ENDS_WITH": [
        ".gserviceaccount.com"
      ]
    }
  }
}
```

This discovered that several of our SaaS services are potentially not following GCP [best practices for managing service account keys](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys) and we plan to privately follow up with them.

The `--out-dir` parameter is useful for running keys through [badkeys](https://github.com/badkeys/badkeys), however we found no examples of such keys in practice. A survey of SA keys looking for issues like duplicate moduli, [shared primes](https://factorable.net/resources.html) or other oddities could be interesting future work, particularly if combined with recon to gather a [large number of](https://sourcegraph.com/search) [SAs to scan](https://cloud.google.com/iam/docs/service-agents).

## Contribution

If you want to submit a PR for bug fixes or documentation, please read the [CONTRIBUTING.md](CONTRIBUTING.md) and follow the instruction beforehand.

## License

The gcp-sa-key-checker is released under the [MIT License](LICENSE).
