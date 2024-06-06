package imageverifier

import (
	"github.com/kyverno/kyverno/pkg/images"
	"github.com/kyverno/kyverno/pkg/registryclient"
	"github.com/vishal-chdhry/cloud-image-verification/pkg/policy"
)

func notaryVerificationOpts(n *policy.Notary, image string) (*images.Options, error) {
	var err error
	opts := &images.Options{
		Cert:     n.Certs,
		ImageRef: image,
	}

	if len(n.Attestations) != 0 {
		opts.FetchAttestations = true
	}

	opts.Client, err = registryclient.New()
	if err != nil {
		return nil, err
	}

	return opts, nil
}

func cosignVerificationOpts(c *policy.Cosign, image string) (*images.Options, error) {
	var err error
	opts := &images.Options{
		ImageRef: image,
	}

	opts.Client, err = registryclient.New()
	if err != nil {
		return nil, err
	}

	if c.Key != nil {
		opts.Key = c.Key.PublicKey
	} else if c.Keyless != nil {
		opts.Issuer = c.Keyless.Issuer
		opts.Subject = c.Keyless.Subject
		opts.Roots = c.Keyless.Root
	} else if c.Certificate != nil {
		opts.Cert = c.Certificate.Cert
		opts.CertChain = c.Certificate.CertChain
	}

	if c.Rekor != nil {
		opts.RekorURL = c.Rekor.URL
		if len(opts.RekorURL) == 0 {
			opts.RekorURL = "https://rekor.sigstore.dev"
		}
		opts.RekorPubKey = c.Rekor.PubKey
	}
	if c.CTLog != nil {
		opts.CTLogsPubKey = c.CTLog.PubKey
	}

	opts.Repository = c.Repository
	opts.SignatureAlgorithm = c.SignatureAlgorithm
	opts.IgnoreSCT = c.IgnoreSCT
	opts.IgnoreTlog = c.IgnoreTlog

	if len(c.InToToAttestations) != 0 {
		opts.FetchAttestations = true
	}

	return opts, nil
}
