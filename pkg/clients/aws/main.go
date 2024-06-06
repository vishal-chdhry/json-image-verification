package aws

import (
	"encoding/json"
	"log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/vishal-chdhry/cloud-image-verification/pkg/imageverifier"
)

func handler(event events.CloudWatchEvent) {
	var eventDetail Detail
	err := json.Unmarshal(event.Detail, &eventDetail)
	if err != nil {
		log.Fatalf("[ERROR] %v error during event unmarshalling: %v", event.ID, err)
	}

	lambdaEvent := LambdaEvent{
		Version:    event.Version,
		ID:         event.ID,
		DetailType: event.DetailType,
		Source:     event.Source,
		Account:    event.AccountID,
		Time:       event.Time,
		Region:     event.Region,
		Resources:  event.Resources,
		Detail:     eventDetail,
	}

	log.Printf("Cluster: %v\n", lambdaEvent.Detail.ClusterArn)
	log.Printf("taskArn: %v\n", lambdaEvent.Detail.TaskArn)
	log.Printf("taskDefinitionArn: %v\n", lambdaEvent.Detail.TaskDefinitionArn)
	log.Printf("accountId: %v\n", lambdaEvent.Account)

	policies, err := getPolicies()
	if err != nil {
		log.Printf("Failed to fetch policies: %v", err)
	}
	iv := imageverifier.NewVerifier(*policies)
	for i := 0; i < len(lambdaEvent.Detail.Containers); i++ {
		log.Printf("Container Image %v : %v", i, lambdaEvent.Detail.Containers[i].Image)
		err := iv.Verify(lambdaEvent.Detail.Containers[i].Image)
		if err != nil {
			log.Printf("Error while verifing image: %v", err)
			log.Printf("%v NOT VERIFIED", lambdaEvent.Detail.Containers[i].Image)
			log.Printf("Stopping Task %v", lambdaEvent.Detail.TaskArn)
			err := stopTask(lambdaEvent.Detail.ClusterArn, lambdaEvent.Detail.TaskArn)
			if err != nil {
				log.Printf("Stopping Task %v : %v", lambdaEvent.Detail.TaskArn, err)
			}

		} else {
			log.Println("VERIFIED")
		}
	}
}

func main() {
	lambda.Start(handler)
}
