package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/nirmata/json-image-verification/pkg/imageverifier"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: ./verifier <POLICY> <RESOURCE>")
	}
	policyPath := flag.String("policy", "", "path to policy")
	resourcePath := flag.String("resource", "", "path to resource")
	flag.Parse()

	b, err := os.ReadFile(*resourcePath)
	if err != nil {
		panic(err)
	}

	var resource interface{}
	if err := json.Unmarshal(b, &resource); err != nil {
		panic(err)
	}

	pol, err := Load(*policyPath)
	if err != nil {
		panic(err)
	}

	verifier := imageverifier.NewEngine()
	request := imageverifier.Request{
		Policies: pol,
		Resource: resource,
	}
	errors := verifier.Apply(request)

	if len(errors) > 0 {
		fmt.Println("Verification failed...")
		for _, err := range errors {
			fmt.Println(err.Error())
		}
		os.Exit(1)
	}
	fmt.Println("Verification succeed!")
}
