package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/kyverno/kyverno/pkg/config"
	"github.com/kyverno/kyverno/pkg/engine/jmespath"
	"github.com/kyverno/kyverno/pkg/logging"
	imageutils "github.com/kyverno/kyverno/pkg/utils/image"
	"github.com/nirmata/json-image-verification/pkg/apis/v1alpha1"
)

type imageExtractor struct {
	Fields   []string
	Key      string
	Value    string
	Name     string
	JMESPath string
}

func (i *imageExtractor) ExtractFromResource(resource interface{}, cfg config.Configuration) (map[string]string, error) {
	imageInfo := map[string]string{}
	if err := extract(resource, []string{}, i.Key, i.Value, i.Fields, i.JMESPath, &imageInfo, cfg); err != nil {
		return nil, err
	}
	return imageInfo, nil
}

func extract(
	obj interface{},
	path []string,
	keyPath string,
	valuePath string,
	fields []string,
	jmesPath string,
	imageInfos *map[string]string,
	cfg config.Configuration,
) error {
	if obj == nil {
		return nil
	}
	if len(fields) > 0 && fields[0] == "*" {
		switch typedObj := obj.(type) {
		case []interface{}:
			for i, v := range typedObj {
				if err := extract(v, append(path, strconv.Itoa(i)), keyPath, valuePath, fields[1:], jmesPath, imageInfos, cfg); err != nil {
					return err
				}
			}
		case map[string]interface{}:
			for i, v := range typedObj {
				if err := extract(v, append(path, i), keyPath, valuePath, fields[1:], jmesPath, imageInfos, cfg); err != nil {
					return err
				}
			}
		case interface{}:
			return fmt.Errorf("invalid type")
		}
		return nil
	}
	output, ok := obj.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid image config")
	}
	if len(fields) == 0 {
		pointer := fmt.Sprintf("/%s/%s", strings.Join(path, "/"), valuePath)
		key := pointer
		if keyPath != "" {
			key, ok = output[keyPath].(string)
			if !ok {
				return fmt.Errorf("invalid key")
			}
		}
		value, ok := output[valuePath].(string)
		if !ok || strings.TrimSpace(value) == "" {
			// the image may not be present
			logging.V(4).Info("image information is not present", "pointer", pointer)
			return nil
		}
		if jmesPath != "" {
			// TODO: should be injected
			jp := jmespath.New(cfg)
			q, err := jp.Query(jmesPath)
			if err != nil {
				return fmt.Errorf("invalid jmespath %s: %v", jmesPath, err)
			}
			result, err := q.Search(value)
			if err != nil {
				return fmt.Errorf("failed to apply jmespath %s: %v", jmesPath, err)
			}
			resultStr, ok := result.(string)
			if !ok {
				return fmt.Errorf("jmespath %s must produce a string, but produced %v", jmesPath, result)
			}
			value = resultStr
		}
		if imageInfo, err := imageutils.GetImageInfo(value, cfg); err != nil {
			return fmt.Errorf("invalid image '%s' (%s)", value, err.Error())
		} else {
			(*imageInfos)[key] = imageInfo.String()
		}
		return nil
	}
	currentPath := fields[0]
	return extract(output[currentPath], append(path, currentPath), keyPath, valuePath, fields[1:], jmesPath, imageInfos, cfg)
}

func lookupImageExtractors(configs v1alpha1.ImageExtractorConfigs) []imageExtractor {
	extractors := []imageExtractor{}
	for _, c := range configs {
		fields := func(input []string) []string {
			output := []string{}
			for _, i := range input {
				o := strings.Trim(i, " ")
				if o != "" {
					output = append(output, o)
				}
			}
			return output
		}(strings.Split(c.Path, "/"))
		name := c.Name
		if name == "" {
			name = "custom"
		}
		value := c.Value
		if value == "" {
			value = fields[len(fields)-1]
			fields = fields[:len(fields)-1]
		}
		extractors = append(extractors, imageExtractor{
			Fields:   fields,
			Key:      c.Key,
			Name:     name,
			Value:    value,
			JMESPath: c.JMESPath,
		})
	}
	return extractors
}

func GetImages(resource interface{}, configs v1alpha1.ImageExtractorConfigs) (map[string]string, error) {
	cfg := config.NewDefaultConfiguration(false)
	extractors := lookupImageExtractors(configs)
	info := map[string]string{}

	for _, extractor := range extractors {
		img, err := extractor.ExtractFromResource(resource, cfg)
		if err != nil {
			return nil, err
		}
		for k, v := range img {
			info[k] = v
		}
	}

	return info, nil
}
