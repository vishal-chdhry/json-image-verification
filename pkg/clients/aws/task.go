package aws

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecs"
)

type NotificationMessage struct {
	Message           string
	ClusterArn        string
	TaskDefinitionArn string
	TaskArn           string
}

func stopTask(clusterArn string, taskArn string) error {
	stopTaskInput := ecs.StopTaskInput{Cluster: aws.String(clusterArn),
		Reason: aws.String("lambda error: image not verified"), Task: aws.String(taskArn)}

	var svc = ecs.New(session.Must(session.NewSession()))

	_, err := svc.StopTask(&stopTaskInput)
	if err != nil {
		return err
	}
	return nil
}
