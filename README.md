# Cloud Image Verification

## Try out

Try out the following command to test different cases
### Cosign Keyed Verification

#### Success case
```bash
go run ./cmd --policy ./cmd/examples/cosign-keyed/policy.yaml --resource ./cmd/examples/cosign-keyed/payload.json
```

#### Failure case
```bash
go run ./cmd --policy ./cmd/examples/cosign-keyed/policy.yaml --resource ./cmd/examples/cosign-keyed/bad-payload.json
```

### Cosign Keyless Verification

#### Success case
```bash
go run ./cmd --policy ./cmd/examples/cosign-keyless/policy.yaml --resource ./cmd/examples/cosign-keyless/payload.json
```

#### Failure case
```bash
go run ./cmd --policy ./cmd/examples/cosign-keyless/policy.yaml --resource ./cmd/examples/cosign-keyless/bad-payload.json
```

### Notary Image Verification
#### Success case
```bash
go run ./cmd --policy ./cmd/examples/notary-image-verification/policy.yaml --resource ./cmd/examples/notary-image-verification/payload.json 
```

#### Failure case
```bash
go run ./cmd --policy ./cmd/examples/notary-image-verification/policy.yaml --resource ./cmd/examples/notary-image-verification/bad-payload.json
```
### Notary Atteastation Verification
#### Success case
```bash
go run ./cmd --policy ./cmd/examples/notary-attestation-verification/policy.yaml --resource ./cmd/examples/notary-attestation-verification/payload.json
```

#### Failure case
```bash
go run ./cmd --policy ./cmd/examples/notary-attestation-verification/policy.yaml --resource ./cmd/examples/notary-attestation-verification/bad-payload.json
```