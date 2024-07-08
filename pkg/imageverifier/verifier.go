package imageverifier

import (
	"context"
	"fmt"

	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	"github.com/kyverno/kyverno/ext/wildcard"
	"github.com/kyverno/kyverno/pkg/config"
	"github.com/kyverno/kyverno/pkg/cosign"
	enginecontext "github.com/kyverno/kyverno/pkg/engine/context"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
	"github.com/kyverno/kyverno/pkg/engine/variables"
	"github.com/kyverno/kyverno/pkg/images"
	"github.com/kyverno/kyverno/pkg/notary"
	"github.com/vishal-chdhry/cloud-image-verification/pkg/apis/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type imageVerifier struct {
	rules          v1alpha1.VerificationRules
	cosignVerifier images.ImageVerifier
	notaryVerifier images.ImageVerifier
	jsonCtx        enginecontext.Interface
}

func NewVerifier(rules v1alpha1.VerificationRules) *imageVerifier {
	return &imageVerifier{
		jsonCtx:        enginecontext.NewContext(jmespath.New(config.NewDefaultConfiguration(false))),
		rules:          rules,
		cosignVerifier: cosign.NewVerifier(),
		notaryVerifier: notary.NewVerifier(),
	}
}

func (i *imageVerifier) Verify(image string) []error {
	errs := make([]error, 0)
	for _, policy := range i.rules {
		if !wildcard.Match(policy.ImageReferences, image) {
			continue
		}

		for _, cosignPolicy := range policy.Cosign {
			if cosignPolicy == nil {
				continue
			}

			err := i.cosignVerification(cosignPolicy, image)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		}

		for _, notaryPolicy := range policy.Notary {
			if notaryPolicy == nil {
				continue
			}

			err := i.notaryVerification(notaryPolicy, image)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		}
	}
	return errs
}

func (i *imageVerifier) cosignVerification(pol *v1alpha1.Cosign, image string) error {
	opts, err := cosignVerificationOpts(pol, image)
	if err != nil {
		return err
	}

	_, err = i.cosignVerifier.VerifySignature(context.TODO(), *opts)
	if err != nil {
		return err
	}

	for _, att := range pol.InToToAttestations {
		if att == nil {
			continue
		}

		o := *opts
		o.Type = att.Type
		_, err := i.cosignVerifier.FetchAttestations(context.Background(), o)
		if err != nil {
			return err
		}
	}
	return nil
}

func (i *imageVerifier) notaryVerification(pol *v1alpha1.Notary, image string) error {
	opts, err := notaryVerificationOpts(pol, image)
	if err != nil {
		return err
	}

	_, err = i.notaryVerifier.VerifySignature(context.Background(), *opts)
	if err != nil {
		return err
	}

	for _, att := range pol.Attestations {
		if att == nil {
			continue
		}

		o := *opts
		o.Type = att.Type
		resp, err := i.notaryVerifier.FetchAttestations(context.Background(), o)
		if err != nil {
			return err
		}
		val, msg, err := i.verifyAttestationConditions(att.Conditions, resp)
		if err != nil {
			return fmt.Errorf("failed to check attestations: %w", err)
		}
		if !val {
			return fmt.Errorf("attestation checks failed for %s and predicate %s: %s", image, att.Type, msg)
		}
	}
	return nil
}

func (i *imageVerifier) verifyAttestationConditions(conditions []kyvernov1.AnyAllConditions, resp *images.Response) (bool, string, error) {
	if len(conditions) == 0 {
		return true, "", nil
	}
	for _, s := range resp.Statements {
		i.jsonCtx.Checkpoint()
		defer i.jsonCtx.Restore()
		logger := log.Log
		predicate, ok := s["predicate"].(map[string]interface{})
		if !ok {
			return false, "", fmt.Errorf("failed to extract predicate from statement: %v", s)
		}
		if err := enginecontext.AddJSONObject(i.jsonCtx, predicate); err != nil {
			return false, "", fmt.Errorf("failed to add Statement to the context %v: %w", s, err)
		}
		c, err := variables.SubstituteAllInConditions(logger, i.jsonCtx, conditions)
		if err != nil {
			return false, "", fmt.Errorf("failed to substitute variables in attestation conditions: %w", err)
		}
		val, msg, err := variables.EvaluateAnyAllConditions(logger, i.jsonCtx, c)
		if !val || err != nil {
			return val, msg, err
		}
	}
	return true, "", nil
}
