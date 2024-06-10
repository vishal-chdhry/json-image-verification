package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kyverno/kyverno-json/pkg/apis/policy/v1alpha1"
)

var (
	allMatchValid = `{
	"all": [
		{
			"apiVersion": "v1",
			"kind": "Pod"
		},
		{
			"metadata": {
				"name": "webserver"
			}
		}
	]
}`

	anyMatchValid = `{
	"any": [
		{
			"apiVersion": "v1",
			"kind": "Pod"
		},
		{
			"apiVersion": "v1",
			"kind": "Deployment"
		}
	]
}
`
	allMatchInvalid = `{
	"all": [
		{
			"apiVersion": "v1",
			"kind": "Pod"
		},
		{
			"apiVersion": "v1",
			"kind": "Deployment"
		}
	]
}
`
	resource = `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "webserver"
  },
  "spec": {
    "containers": [
      {
        "name": "webserver-1",
        "image": "nginx:latest",
        "ports": [
          {
            "containerPort": 80
          }
        ]
      },
      {
        "name": "webserver-2",
        "image": "nginx:latest",
        "ports": [
          {
            "containerPort": 80
          }
        ]
      },
      {
        "name": "webserver-3",
        "image": "nginx:latest",
        "ports": [
          {
            "containerPort": 80
          }
        ]
      }
    ]
  }
}
`
)

func Test_Match(t *testing.T) {
	tests := []struct {
		name     string
		match    string
		resource string
		wantErr  bool
	}{
		{
			name:     "all match valid",
			match:    allMatchValid,
			resource: resource,
			wantErr:  false,
		},
		{
			name:     "any match valid",
			match:    anyMatchValid,
			resource: resource,
			wantErr:  false,
		},
		{
			name:     "all match invalid",
			match:    allMatchInvalid,
			resource: resource,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var res interface{}
			if err := json.Unmarshal([]byte(tt.resource), &res); err != nil {
				t.Fatal(err)
			}

			var match v1alpha1.Match
			if err := json.Unmarshal([]byte(tt.match), &match); err != nil {
				t.Fatal(err)
			}
			errs, err := Match(context.Background(), match, res)
			if err != nil {
				t.Fatal(err)
			}

			if (len(errs) > 0) != tt.wantErr {
				t.Errorf("test failed, wantErr=%v, gotErr=%v", tt.wantErr, errs)
			}

		})
	}
}
