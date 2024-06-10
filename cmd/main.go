package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/vishal-chdhry/cloud-image-verification/pkg/imageverifier"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Println("usage: ./verifier <POLICY> <RESOURCE>")
	}

	policyPath := os.Args[1]
	resourcePath := os.Args[2]

	b, err := os.ReadFile(resourcePath)
	if err != nil {
		panic(err)
	}

	var resource interface{}
	if err := json.Unmarshal(b, &resource); err != nil {
		panic(err)
	}

	pol, err := Load(policyPath)
	if err != nil {
		panic(err)
	}

	verifier := imageverifier.NewEngine(pol)
	errors := verifier.Apply(resource)

	if len(errors) > 0 {
		fmt.Println("Verification failed...")
		for _, err := range errors {
			fmt.Println(err.Error())
		}
		os.Exit(1)
	}
	fmt.Println("Verification succeed!")
}
