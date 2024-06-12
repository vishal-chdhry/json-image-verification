package policy

import (
	"encoding/json"
	"testing"

	"github.com/vishal-chdhry/cloud-image-verification/pkg/apis/v1alpha1"
	"gotest.tools/assert"
)

var taskDefinition = `
{
   "containerDefinitions": [ 
      { 
         "command": [
            "/bin/sh -c \"echo '<html> <head> <title>Amazon ECS Sample App</title> <style>body {margin-top: 40px; background-color: #333;} </style> </head><body> <div style=color:white;text-align:center> <h1>Amazon ECS Sample App</h1> <h2>Congratulations!</h2> <p>Your application is now running on a container in Amazon ECS.</p> </div></body></html>' >  /usr/local/apache2/htdocs/index.html && httpd-foreground\""
         ],
         "entryPoint": [
            "sh",
            "-c"
         ],
         "essential": true,
         "image": "httpd:2.4",
         "logConfiguration": { 
            "logDriver": "awslogs",
            "options": { 
               "awslogs-group" : "/ecs/fargate-task-definition",
               "awslogs-region": "us-east-1",
               "awslogs-stream-prefix": "ecs"
            }
         },
         "name": "sample-fargate-app",
         "portMappings": [ 
            { 
               "containerPort": 80,
               "hostPort": 80,
               "protocol": "tcp"
            }
         ]
      }
   ],
   "cpu": "256",
   "executionRoleArn": "arn:aws:iam::012345678910:role/ecsTaskExecutionRole",
   "family": "fargate-task-definition",
   "memory": "512",
   "networkMode": "awsvpc",
   "runtimePlatform": {
        "operatingSystemFamily": "LINUX"
    },
   "requiresCompatibilities": [ 
       "FARGATE" 
    ]
}
`

func Test_Extractor(t *testing.T) {
	tests := []struct {
		name       string
		resource   string
		extractors v1alpha1.ImageExtractorConfigs
		images     map[string]string
		wantErr    bool
	}{
		{
			name:     "valid path",
			resource: taskDefinition,
			extractors: []v1alpha1.ImageExtractorConfig{
				{
					Name: "test",
					Path: "/containerDefinitions/*/image/",
				},
			},
			images: map[string]string{
				"/containerDefinitions/0/image": "docker.io/httpd:2.4",
			},
		},
		{
			name:     "path not found",
			resource: taskDefinition,
			extractors: []v1alpha1.ImageExtractorConfig{
				{
					Name: "test",
					Path: "/containerDefinitions/*/invalid/",
				},
			},
			images: map[string]string{},
		},
		{
			name:     "invalid path",
			resource: taskDefinition,
			extractors: []v1alpha1.ImageExtractorConfig{
				{
					Name: "test",
					Path: "/containerDefinitions/0/image/",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			object := map[string]interface{}{}
			if err := json.Unmarshal([]byte(tt.resource), &object); err != nil {
				t.Fatal(err)
			}
			got, err := GetImages(object, tt.extractors)
			if (err != nil) != tt.wantErr {
				t.Fatal(err)
			}

			assert.Equal(t, len(got), len(tt.images))
			for k, v := range got {
				assert.Equal(t, tt.images[k], v)
			}
		})
	}
}
