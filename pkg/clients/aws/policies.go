package aws

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/vishal-chdhry/cloud-image-verification/pkg/policy"
)

func getPolicies() (*policy.VerificationPolicies, error) {
	pol := os.Getenv("VERIFICATION_POLICIES")
	if len(pol) != 0 {
		return nil, errors.New("must provide VERIFICATION_POLICIES")
	}
	var validationPolicies policy.VerificationPolicies
	if err := json.Unmarshal([]byte(pol), &validationPolicies); err != nil {
		return nil, fmt.Errorf("invalid validation policy provided: %w", err)
	}
	return &validationPolicies, nil
}
