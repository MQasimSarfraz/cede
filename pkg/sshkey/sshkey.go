package sshkey

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

func Execute() {
	sess := session.Must(session.NewSession())

	iamClient := iam.New(sess)

	ret, _ := iamClient.ListUsers(&iam.ListUsersInput{})

	for _, user := range ret.Users {
		input := &iam.ListSSHPublicKeysInput{UserName: user.UserName}
		resp, err := iamClient.ListSSHPublicKeys(input)
		if err != nil {
			panic(err)
		}
		fmt.Println(resp)
	}
}
