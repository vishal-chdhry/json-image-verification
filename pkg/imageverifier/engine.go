package imageverifier

import (
	"context"
	"fmt"

	"github.com/vishal-chdhry/cloud-image-verification/pkg/apis/v1alpha1"
	"github.com/vishal-chdhry/cloud-image-verification/pkg/policy"
)

type engine struct{}

type Request struct {
	Policies []*v1alpha1.ImageVerificationPolicy
	Resource interface{}
}

func NewEngine() *engine {
	return &engine{}
}

func (e *engine) Apply(request Request) []error {
	var errors []error
	for _, pol := range request.Policies {
		for _, r := range pol.Spec.Rules {
			errs, err := policy.Match(context.Background(), r.Match, request.Resource)
			if err != nil {
				errors = append(errors, err)
				return errors
			}
			if len(errs) > 0 {
				continue
			}

			verifier := NewVerifier(r.Rules)
			images, err := policy.GetImages(request.Resource, r.ImageExtractor)
			if err != nil {
				errors = append(errors, err)
				return errors
			}
			for _, v := range images {
				errs := verifier.Verify(v)
				for _, err := range errs {
					errors = append(errors, fmt.Errorf("policy: %s, rule: %s, image: %s, error: %w", pol.Name, r.Name, v, err))
				}
			}
		}
	}
	return errors
}
