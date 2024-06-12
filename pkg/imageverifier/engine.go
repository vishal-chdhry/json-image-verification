package imageverifier

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vishal-chdhry/cloud-image-verification/pkg/apis/v1alpha1"
	"github.com/vishal-chdhry/cloud-image-verification/pkg/policy"
)

type engine struct {
	policies []*v1alpha1.ImageVerificationPolicy
}

func NewEngine(policies []*v1alpha1.ImageVerificationPolicy) *engine {
	return &engine{
		policies: policies,
	}
}

func (e *engine) Apply(resource interface{}) []error {
	var errors []error
	for _, pol := range e.policies {
		for _, r := range pol.Spec.Rules {
			errs, err := policy.Match(context.Background(), r.Match, resource)
			if err != nil {
				errors = append(errors, err)
				return errors
			}
			if len(errs) > 0 {
				b, _ := json.Marshal(r.Match)
				fmt.Println("skipping", errs, string(b))
				continue
			}

			verifier := NewVerifier(r.Rules)
			images, err := policy.GetImages(resource, r.ImageExtractor)
			if err != nil {
				errors = append(errors, err)
				return errors
			}
			for _, v := range images {
				fmt.Println("found image:", v)
				err := verifier.Verify(v)
				if err != nil {
					errors = append(errors, fmt.Errorf("Policy: %s, rule: %s, image: %s, error: %w", pol.Name, r.Name, v, err))
				}
			}
		}
	}
	return errors
}
