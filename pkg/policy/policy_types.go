package policy

import "fmt"

var (
	multipleAttestorError = fmt.Errorf("mutliple attestor cannot be added in the same entry")
)

// VerificationPolicies is a set of VerificationPolicy
type VerificationPolicies []VerificationPolicy

// VerificationPolicy is a rule against which images are validated.
type VerificationPolicy struct {
	// ImageReferences is a list of matching image reference patterns. At least one pattern in the
	// list must match the image for the rule to apply. Each image reference consists of a registry
	// address, repository, image, and tag (defaults to latest). Wildcards ('*' and '?') are allowed.
	ImageReferences string `json:"imageReferences"`

	// Cosign is an array of attributes used to verify cosign signatures
	Cosign []*Cosign `json:"cosign,omitempty"`

	// Notary is an array of attributes used to verify notary signatures
	Notary []*Notary `json:"notary,omitempty"`
}

// Cosign is a set of attributes used to verify cosign signatures
type Cosign struct {
	Key                *Key           `json:"key,omitempty"`
	Keyless            *Keyless       `json:"keyless,omitempty"`
	Certificate        *Certificate   `json:"certificate,omitempty"`
	Rekor              *Rekor         `json:"rekor,omitempty"`
	CTLog              *CTLog         `json:"ctlog,omitempty"`
	SignatureAlgorithm string         `json:"signatureAlgorithm,omitempty"`
	Repository         string         `json:"repository,omitempty"`
	IgnoreTlog         bool           `json:"ignoreTlog"`
	IgnoreSCT          bool           `json:"ignoreSCT"`
	TSACertChain       string         `json:"tsaCertChain"`
	InToToAttestations []*Attestation `json:"intotoAttestations,omitempty"`
}

type Key struct {
	PublicKey string `json:"publicKey"`
}

type Keyless struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	Root    string `json:"root"`
}

type Certificate struct {
	Cert      string `json:"cert"`
	CertChain string `json:"certChain"`
}

type Rekor struct {
	URL    string `json:"url"`
	PubKey string `json:"pubKey"`
}

type CTLog struct {
	PubKey string `json:"pubKey"`
}

// Notary is a set of attributes used to verify notary signatures
type Notary struct {
	Certs        string         `json:"certs"`
	Attestations []*Attestation `json:"attestations"`
}

type Attestation struct {
	Type string `json:"type"`
}

func (v *VerificationPolicy) Validate() error {
	for _, v := range v.Cosign {
		if v != nil {
			attestorAlreadyExists := false
			if v.Key != nil {
				if attestorAlreadyExists {
					return multipleAttestorError
				}
				attestorAlreadyExists = true
			}
			if v.Keyless != nil {
				if attestorAlreadyExists {
					return multipleAttestorError
				}
				attestorAlreadyExists = true
			}
			if v.Certificate != nil {
				if attestorAlreadyExists {
					return multipleAttestorError
				}
				attestorAlreadyExists = true
			}
		}
	}
	return nil
}
