package cede

import (
	"fmt"
	"github.com/MQasimSarfraz/cede/pkg/config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/pkg/errors"
	"strings"
)

// PrintIAMKey us used to print the  public key for the given username
func PrintIAMKey(username string) error {
	sess := session.Must(session.NewSession())
	iamClient := iam.New(sess)
	listUsers, err := iamClient.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		return errors.WithMessage(err, "getting users")
	}

	// read the config
	cfg, err := config.Read(config.GetOrDefaultPath())

	// filter the users based on allowed domains
	userAddresses := filterAddressesByDomains(listUsers.Users, cfg.AllowedDomains...)

	// make sure given username exists in IAM
	uAddress, ok := verifyUserExistsInIAM(userAddresses, username)
	if !ok {
		return errors.Errorf("user=%s not present in IAM", username)
	}

	// get the key id for user
	listKeysInput := &iam.ListSSHPublicKeysInput{UserName: &uAddress}
	listKeysOutput, err := iamClient.ListSSHPublicKeys(listKeysInput)
	if err != nil {
		return errors.WithMessage(err, "getting key id")
	}

	// get the first active key for user
	keyId := firstActiveKeyId(listKeysOutput.SSHPublicKeys)
	if keyId == nil {
		return errors.Errorf("no key for user=%s", username)
	}

	// get and print the key content
	getKeysInput := &iam.GetSSHPublicKeyInput{
		Encoding:       aws.String(iam.EncodingTypeSsh),
		SSHPublicKeyId: keyId,
		UserName:       &uAddress,
	}

	getKeysOutput, err := iamClient.GetSSHPublicKey(getKeysInput)
	if err != nil {
		return errors.WithMessage(err, "getting key")
	}
	fmt.Print(*getKeysOutput.SSHPublicKey.SSHPublicKeyBody)

	return nil
}

// PrintIAMUsers prints the permitted users in IAM
func PrintIAMUsers() error {
	cfg, err := config.Read(config.GetOrDefaultPath())
	if err != nil {
		return errors.WithMessage(err, "reading config")
	}

	// get all the users
	var users []string
	sess := session.Must(session.NewSession())
	iamClient := iam.New(sess)
	for _, group := range cfg.Groups {
		groupInput := iam.GetGroupInput{GroupName: &group.Name}
		groupOutput, err := iamClient.GetGroup(&groupInput)
		if err != nil {
			return errors.WithMessage(err, "getting iam group")
		}
		for _, user := range groupOutput.Users {
			users = append(users, *user.UserName)
		}
	}

	// print all the users
	for _, user := range unique(users) {
		println(user)
	}

	return nil
}

func filterAddressesByDomains(iamUsers []*iam.User, domains ...string) []string {
	var addresses []string
	for _, user := range iamUsers {
		// ignore errors regarding missing domains
		domain, _ := domainOf(*user.UserName)
		if contains(domains, domain) {
			addresses = append(addresses, *user.UserName)
		}
	}
	return addresses
}

func firstActiveKeyId(keys []*iam.SSHPublicKeyMetadata) *string {
	for _, key := range keys {
		if *key.Status == iam.StatusTypeActive {
			return key.SSHPublicKeyId
		}
	}
	return nil
}

func verifyUserExistsInIAM(addresses []string, username string) (string, bool) {
	for _, address := range addresses {
		un, _ := usernameOf(address)
		if strings.ToLower(un) == strings.ToLower(username) {
			return address, true
		}
	}
	return "", false
}

func domainOf(address string) (string, error) {
	// TODO: may be care about multiple '@'
	mail := strings.Split(address, "@")
	if len(mail) != 2 {
		return "", errors.Errorf("parsing address=%s", address)
	}
	return mail[1], nil
}

func usernameOf(address string) (string, error) {
	// TODO: may be care about multiple '@'
	mail := strings.Split(address, "@")
	if len(mail) != 2 {
		return "", errors.Errorf("parsing address=%s", address)
	}
	return mail[0], nil
}

func contains(list []string, given string) bool {
	for _, item := range list {
		if item == given {
			return true
		}
	}
	return false
}

func unique(s []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range s {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
