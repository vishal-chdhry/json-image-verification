package imageverifier

import (
	"context"

	"github.com/kyverno/kyverno/ext/wildcard"
	"github.com/kyverno/kyverno/pkg/cosign"
	"github.com/kyverno/kyverno/pkg/images"
	"github.com/kyverno/kyverno/pkg/notary"
	"github.com/vishal-chdhry/cloud-image-verification/pkg/policy"
)

type imageVerifier struct {
	rules          policy.VerificationRules
	cosignVerifier images.ImageVerifier
	notaryVerifier images.ImageVerifier
}

func NewVerifier(rules policy.VerificationRules) *imageVerifier {
	return &imageVerifier{
		rules:          rules,
		cosignVerifier: cosign.NewVerifier(),
		notaryVerifier: notary.NewVerifier(),
	}
}

func (i *imageVerifier) Verify(image string) error {
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
				return err
			}
		}

		for _, notaryPolicy := range policy.Notary {
			if notaryPolicy == nil {
				continue
			}

			err := i.notaryVerification(notaryPolicy, image)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *imageVerifier) cosignVerification(pol *policy.Cosign, image string) error {
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

func (i *imageVerifier) notaryVerification(pol *policy.Notary, image string) error {
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
		_, err := i.notaryVerifier.FetchAttestations(context.Background(), o)
		if err != nil {
			return err
		}
	}
	return nil
}
