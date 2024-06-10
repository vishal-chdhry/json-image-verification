package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"

	fileinfo "github.com/kyverno/pkg/ext/file-info"
	yamlutils "github.com/kyverno/pkg/ext/yaml"
	"github.com/vishal-chdhry/cloud-image-verification/pkg/policy"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	gv                      = schema.GroupVersion{Group: "nirmata.io", Version: "v1alpha1"}
	imageVerificationPolicy = gv.WithKind("ImageVerificationPolicy")
)

func Load(path ...string) ([]*policy.ImageVerificationPolicy, error) {
	var policies []*policy.ImageVerificationPolicy
	for _, path := range path {
		p, err := load(path)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p...)
	}
	return policies, nil
}

func load(path string) ([]*policy.ImageVerificationPolicy, error) {
	var files []string
	err := filepath.Walk(path, func(file string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fileinfo.IsJson(info) {
			files = append(files, file)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var policies []*policy.ImageVerificationPolicy
	for _, path := range files {
		content, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil, err
		}
		p, err := Parse(content)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p...)
	}
	return policies, nil
}

func Parse(content []byte) ([]*policy.ImageVerificationPolicy, error) {
	documents, err := yamlutils.SplitDocuments(content)
	if err != nil {
		return nil, err
	}
	var policies []*policy.ImageVerificationPolicy
	for _, document := range documents {
		// fmt.Println(string(document))
		var pol policy.ImageVerificationPolicy
		if err := json.Unmarshal(document, &pol); err != nil {
			return nil, err
		}
		policies = append(policies, &pol)
	}
	return policies, nil
}
