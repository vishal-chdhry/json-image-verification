package policy

import (
	"context"

	"github.com/kyverno/kyverno-json/pkg/apis/policy/v1alpha1"
	"github.com/kyverno/kyverno-json/pkg/matching"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func Match(ctx context.Context, condition v1alpha1.Match, resource interface{}) (field.ErrorList, error) {
	return matching.Match(ctx, nil, &condition, resource, nil)
}
