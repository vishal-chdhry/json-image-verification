package imageverifier

import (
	"encoding/json"
	"testing"

	"github.com/vishal-chdhry/cloud-image-verification/pkg/policy"
)

func Test_Verifier(t *testing.T) {
	tests := []struct {
		name    string
		rules   string
		image   string
		wantErr bool
	}{
		{
			name:    "cosign keyed verification",
			rules:   `[{"imageReferences":"ghcr.io/kyverno/test-verify-image*","cosign":[{"key":{"publicKey":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8nXRh950IZbRj8Ra/N9sbqOPZrfM\n5/KAQN0/KjHcorm/J5yctVd7iEcnessRQjU917hmKO6JWVGHpDguIyakZA==\n-----END PUBLIC KEY-----"},"ignoreTlog":true}]}]`,
			image:   "ghcr.io/kyverno/test-verify-image:signed",
			wantErr: false,
		},
		{
			name:    "cosign keyed verification failed",
			rules:   `[{"imageReferences":"ghcr.io/kyverno/test-verify-image*","cosign":[{"key":{"publicKey":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8nXRh950IZbRj8Ra/N9sbqOPZrfM\n5/KAQN0/KjHcorm/J5yctVd7iEcnessRQjU917hmKO6JWVGHpDguIyakZA==\n-----END PUBLIC KEY-----"},"ignoreTlog":true}]}]`,
			image:   "ghcr.io/kyverno/test-verify-image:signed-cert",
			wantErr: true,
		},
		{
			name:    "cosign cert verification",
			rules:   `[{"imageReferences":"ghcr.io/kyverno/test-verify-image:signed-cert","cosign":[{"certificate":{"certChain":"-----BEGIN CERTIFICATE-----\nMIIDuTCCAqGgAwIBAgIUU1kkhcMc+7ci1qvkLCre5lbH68owDQYJKoZIhvcNAQEL\nBQAwbDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQwwCgYDVQQHDANTSkMxEDAO\nBgNVBAoMB05pcm1hdGExEDAOBgNVBAMMB25pcm1hdGExHjAcBgkqhkiG9w0BCQEW\nD2ppbUBuaXJtYXRhLmNvbTAeFw0yMjA0MjgxOTE2NTJaFw0yNzA0MjcxOTE2NTJa\nMGwxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEMMAoGA1UEBwwDU0pDMRAwDgYD\nVQQKDAdOaXJtYXRhMRAwDgYDVQQDDAduaXJtYXRhMR4wHAYJKoZIhvcNAQkBFg9q\naW1AbmlybWF0YS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCx\nhpgJ/YUXtUyLNjJgoOBQHSIL6PrdNj9iemgddVg1WGzQrtMnleVY1Wh31C3nV2oN\nVrcH2+i/14fyTWpAPEoJ/E6/3Pd8EYokFffm6AXvSCX6gaRpgeiWySK9T62bI7TP\n4VplppF4lkUJbYxtFiVt5q2T4+lm+k8Q5kDtxU8d1067ApM82f9kHgoLqJwuuGM7\nVPHX023orJ2YU68gJo78qGbv+1/aoPpcEZelk5RBXplvOT23DbMgEi3SxWjJ3djU\nsvQu+FMLG9xWpTdH5P98/1hY89xxYk+paEVDX0xSmINt2nfFGV5x1ChEMaZSC/7Q\n9Z5qRX2e26/Mm+jFnIIJAgMBAAGjUzBRMB0GA1UdDgQWBBQRd7sB6L7MY+1sUrww\nygU8LkfqGjAfBgNVHSMEGDAWgBQRd7sB6L7MY+1sUrwwygU8LkfqGjAPBgNVHRMB\nAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCGMBvR7wGHQdofwP4rCeXY9OlR\nRamGcOX7GLI5zQnO717l+kZqJQAQfhgehbm14UkXx3/1iyqSYpNUIeY6XZaiAxMC\nfQI8ufcaws4f522QINGNLQGzzt2gkDAg25ARTgH4JVmRxiViTsfrb+VgjcYhkLK5\nmWffp3LpCiybZaRKwS93SNWo95ld2VzDgzGNLLGejifCe9nPSfvkuXHfDW9nSRMP\nplXrFYd7TTMUaENRmTQtl1KyIlnLEp+A6ZBpY1Pxdc9SnflYQVQb0hsxSa+Swkb6\nhRkMf01X7+GAI75hpgoX/CuCjd8J5kozsXLzUtKRop5gXyZxuFL8yUW9gfQs\n-----END CERTIFICATE-----"},"ignoreSCT":true,"ignoreTlog":true}]}]`,
			image:   "ghcr.io/kyverno/test-verify-image:signed-cert",
			wantErr: false,
		},
		{
			name:    "cosign keyless image verification",
			rules:   `[{"imageReferences":"ghcr.io/vishal-chdhry/*","cosign":[{"keyless":{"issuer":"https://accounts.google.com","subject":"vishal.choudhary@nirmata.com"},"rekor":{"pubKey":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----"},"ignoreSCT":true}]}]`,
			image:   "ghcr.io/vishal-chdhry/cosign-test:v1",
			wantErr: false,
		},
		{
			name:    "cosign keyless image verification skip",
			rules:   `[{"imageReferences":"ghcr.io/vishal-chdhry/*","cosign":[{"keyless":{"issuer":"https://accounts.google.com","subject":"vishal.choudhary@nirmata.com"},"rekor":{"pubKey":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----"},"ignoreSCT":true}]}]`,
			image:   "ghcr.io/invalid-usr/cosign-test:v1",
			wantErr: false,
		},
		{
			name:    "cosign keyless image verification invalid image",
			rules:   `[{"imageReferences":"ghcr.io/vishal-chdhry/*","cosign":[{"keyless":{"issuer":"https://accounts.google.com","subject":"vishal.choudhary@nirmata.com"},"rekor":{"pubKey":"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\nkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n-----END PUBLIC KEY-----"},"ignoreSCT":true}]}]`,
			image:   "ghcr.io/vishal-chdhry/cosign-test:invalid",
			wantErr: true,
		},
		{
			name:    "notary attestation verification",
			rules:   `[{"imageReferences":"ghcr.io/kyverno/test-verify-image*","notary":[{"certs":"-----BEGIN CERTIFICATE-----\nMIIDTTCCAjWgAwIBAgIJAPI+zAzn4s0xMA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwG\nTm90YXJ5MQ0wCwYDVQQDDAR0ZXN0MB4XDTIzMDUyMjIxMTUxOFoXDTMzMDUxOTIx\nMTUxOFowTDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdTZWF0\ndGxlMQ8wDQYDVQQKDAZOb3RhcnkxDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQDNhTwv+QMk7jEHufFfIFlBjn2NiJaYPgL4eBS+\nb+o37ve5Zn9nzRppV6kGsa161r9s2KkLXmJrojNy6vo9a6g6RtZ3F6xKiWLUmbAL\nhVTCfYw/2n7xNlVMjyyUpE+7e193PF8HfQrfDFxe2JnX5LHtGe+X9vdvo2l41R6m\nIia04DvpMdG4+da2tKPzXIuLUz/FDb6IODO3+qsqQLwEKmmUee+KX+3yw8I6G1y0\nVp0mnHfsfutlHeG8gazCDlzEsuD4QJ9BKeRf2Vrb0ywqNLkGCbcCWF2H5Q80Iq/f\nETVO9z88R7WheVdEjUB8UrY7ZMLdADM14IPhY2Y+tLaSzEVZAgMBAAGjMjAwMAkG\nA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0G\nCSqGSIb3DQEBCwUAA4IBAQBX7x4Ucre8AIUmXZ5PUK/zUBVOrZZzR1YE8w86J4X9\nkYeTtlijf9i2LTZMfGuG0dEVFN4ae3CCpBst+ilhIndnoxTyzP+sNy4RCRQ2Y/k8\nZq235KIh7uucq96PL0qsF9s2RpTKXxyOGdtp9+HO0Ty5txJE2txtLDUIVPK5WNDF\nByCEQNhtHgN6V20b8KU2oLBZ9vyB8V010dQz0NRTDLhkcvJig00535/LUylECYAJ\n5/jn6XKt6UYCQJbVNzBg/YPGc1RF4xdsGVDBben/JXpeGEmkdmXPILTKd9tZ5TC0\nuOKpF5rWAruB5PCIrquamOejpXV9aQA/K2JQDuc0mcKz\n-----END CERTIFICATE-----","attestations":[{"type":"sbom/cyclone-dx"}]}]}]`,
			image:   "ghcr.io/kyverno/test-verify-image:signed",
			wantErr: false,
		},
		{
			name:    "notary image verification",
			rules:   `[{"imageReferences":"ghcr.io/kyverno/test-verify-image*","notary":[{"certs":"-----BEGIN CERTIFICATE-----\nMIIDTTCCAjWgAwIBAgIJAPI+zAzn4s0xMA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwG\nTm90YXJ5MQ0wCwYDVQQDDAR0ZXN0MB4XDTIzMDUyMjIxMTUxOFoXDTMzMDUxOTIx\nMTUxOFowTDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdTZWF0\ndGxlMQ8wDQYDVQQKDAZOb3RhcnkxDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQDNhTwv+QMk7jEHufFfIFlBjn2NiJaYPgL4eBS+\nb+o37ve5Zn9nzRppV6kGsa161r9s2KkLXmJrojNy6vo9a6g6RtZ3F6xKiWLUmbAL\nhVTCfYw/2n7xNlVMjyyUpE+7e193PF8HfQrfDFxe2JnX5LHtGe+X9vdvo2l41R6m\nIia04DvpMdG4+da2tKPzXIuLUz/FDb6IODO3+qsqQLwEKmmUee+KX+3yw8I6G1y0\nVp0mnHfsfutlHeG8gazCDlzEsuD4QJ9BKeRf2Vrb0ywqNLkGCbcCWF2H5Q80Iq/f\nETVO9z88R7WheVdEjUB8UrY7ZMLdADM14IPhY2Y+tLaSzEVZAgMBAAGjMjAwMAkG\nA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0G\nCSqGSIb3DQEBCwUAA4IBAQBX7x4Ucre8AIUmXZ5PUK/zUBVOrZZzR1YE8w86J4X9\nkYeTtlijf9i2LTZMfGuG0dEVFN4ae3CCpBst+ilhIndnoxTyzP+sNy4RCRQ2Y/k8\nZq235KIh7uucq96PL0qsF9s2RpTKXxyOGdtp9+HO0Ty5txJE2txtLDUIVPK5WNDF\nByCEQNhtHgN6V20b8KU2oLBZ9vyB8V010dQz0NRTDLhkcvJig00535/LUylECYAJ\n5/jn6XKt6UYCQJbVNzBg/YPGc1RF4xdsGVDBben/JXpeGEmkdmXPILTKd9tZ5TC0\nuOKpF5rWAruB5PCIrquamOejpXV9aQA/K2JQDuc0mcKz\n-----END CERTIFICATE-----"}]}]`,
			image:   "ghcr.io/kyverno/test-verify-image:signed",
			wantErr: false,
		},
		{
			name:    "notary image verification fail",
			rules:   `[{"imageReferences":"ghcr.io/kyverno/test-verify-image*","notary":[{"certs":"-----BEGIN CERTIFICATE-----\nMIIDTTCCAjWgAwIBAgIJAPI+zAzn4s0xMA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwG\nTm90YXJ5MQ0wCwYDVQQDDAR0ZXN0MB4XDTIzMDUyMjIxMTUxOFoXDTMzMDUxOTIx\nMTUxOFowTDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdTZWF0\ndGxlMQ8wDQYDVQQKDAZOb3RhcnkxDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQDNhTwv+QMk7jEHufFfIFlBjn2NiJaYPgL4eBS+\nb+o37ve5Zn9nzRppV6kGsa161r9s2KkLXmJrojNy6vo9a6g6RtZ3F6xKiWLUmbAL\nhVTCfYw/2n7xNlVMjyyUpE+7e193PF8HfQrfDFxe2JnX5LHtGe+X9vdvo2l41R6m\nIia04DvpMdG4+da2tKPzXIuLUz/FDb6IODO3+qsqQLwEKmmUee+KX+3yw8I6G1y0\nVp0mnHfsfutlHeG8gazCDlzEsuD4QJ9BKeRf2Vrb0ywqNLkGCbcCWF2H5Q80Iq/f\nETVO9z88R7WheVdEjUB8UrY7ZMLdADM14IPhY2Y+tLaSzEVZAgMBAAGjMjAwMAkG\nA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA0G\nCSqGSIb3DQEBCwUAA4IBAQBX7x4Ucre8AIUmXZ5PUK/zUBVOrZZzR1YE8w86J4X9\nkYeTtlijf9i2LTZMfGuG0dEVFN4ae3CCpBst+ilhIndnoxTyzP+sNy4RCRQ2Y/k8\nZq235KIh7uucq96PL0qsF9s2RpTKXxyOGdtp9+HO0Ty5txJE2txtLDUIVPK5WNDF\nByCEQNhtHgN6V20b8KU2oLBZ9vyB8V010dQz0NRTDLhkcvJig00535/LUylECYAJ\n5/jn6XKt6UYCQJbVNzBg/YPGc1RF4xdsGVDBben/JXpeGEmkdmXPILTKd9tZ5TC0\nuOKpF5rWAruB5PCIrquamOejpXV9aQA/K2JQDuc0mcKz\n-----END CERTIFICATE-----"}]}]`,
			image:   "ghcr.io/kyverno/test-verify-image:signed-cert",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ivRules policy.VerificationRules
			if err := json.Unmarshal([]byte(tt.rules), &ivRules); err != nil {
				t.Fatalf("failed to unmarshal rules: %v", err)
			}

			verifier := NewVerifier(ivRules)
			if err := verifier.Verify(tt.image); (err != nil) != tt.wantErr {
				t.Errorf("test failed, wantErr: %v, got error: %v", tt.wantErr, err)
			}
		})
	}
}
