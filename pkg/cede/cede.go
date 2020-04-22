package cede

import (
	"fmt"
	"github.com/MQasimSarfraz/cede/pkg/config"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/peterbourgon/diskv"
	"github.com/pkg/errors"
	"os"
	"path"
	"strings"
	"time"
)

const CachePath = "/tmp/cede-cache"

var ErrKeyNotFound = errors.New("key not found")

var cache = diskv.New(diskv.Options{
	BasePath:     CachePath,
	Transform:    func(s string) []string { return []string{} },
	CacheSizeMax: 64 * 1024,
})

// PrintIAMKey is used to print the  public key for the given username
func PrintIAMKey(username string) error {
	// read the config
	cfg, err := config.Read(config.GetOrDefaultPath())
	if err != nil {
		return errors.WithMessage(err, "reading config")
	}

	// noop for external users
	for _, user := range cfg.ExternalUsers {
		if user == username {
			return nil
		}
	}

	// check if key exists in cache
	if key, ok := keyFromCache(username, cfg.CacheLifeTime); ok {
		fmt.Println(key)
		return nil
	}

	// fall back to fetch from IAM
	if key, kErr := keyFromIAM(username, cfg); kErr == nil {
		fmt.Println(key)
		return nil
	}

	return ErrKeyNotFound
}

// PrintIAMUsers prints the permitted
func PrintIAMUsers() error {
	cfg, err := config.Read(config.GetOrDefaultPath())
	if err != nil {
		return errors.WithMessage(err, "reading config")
	}

	// get all the users
	users, err := usersFromIAM(cfg)
	if err != nil {
		return errors.WithMessage(err, "getting users from iam")
	}

	// print all the users
	fmt.Println(strings.Join(users, "\n"))

	return nil
}

// Imports the permitted users in linux
func ImportUserFromIAM() error {
	panic("Implement me")
}

func keyFromIAM(username string, cfg *config.Config) (string, error) {
	// fetch users from IAM
	sess := session.Must(session.NewSession())
	iamClient := iam.New(sess)
	listUsers, err := iamClient.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		return "", errors.WithMessage(err, "getting users")
	}

	// filter the users based on allowed domains
	userAddresses := filterAddressesByDomains(listUsers.Users, cfg.AllowedDomains...)

	// make sure given username exists in IAM
	uAddress, ok := verifyUserExistsInIAM(userAddresses, username)
	if !ok {
		return "", errors.Errorf("user=%s not present in IAM", username)
	}

	// get the key id for user
	listKeysInput := &iam.ListSSHPublicKeysInput{UserName: &uAddress}
	listKeysOutput, err := iamClient.ListSSHPublicKeys(listKeysInput)
	if err != nil {
		return "", errors.WithMessage(err, "getting key id")
	}

	// get the first active key for user
	keyId := firstActiveKeyId(listKeysOutput.SSHPublicKeys)
	if keyId == nil {
		return "", errors.Errorf("no key for user=%s", username)
	}

	// get and print the key content
	getKeysInput := &iam.GetSSHPublicKeyInput{
		Encoding:       aws.String(iam.EncodingTypeSsh),
		SSHPublicKeyId: keyId,
		UserName:       &uAddress,
	}

	getKeysOutput, err := iamClient.GetSSHPublicKey(getKeysInput)
	if err != nil {
		return "", errors.WithMessage(err, "getting key")
	}

	// add the key to cache as well
	err = cache.Write(username, []byte(*getKeysOutput.SSHPublicKey.SSHPublicKeyBody))
	if err != nil {
		return "", errors.WithMessage(err, "writing to cache")
	}

	return *getKeysOutput.SSHPublicKey.SSHPublicKeyBody, nil
}

func keyFromCache(username string, cacheLifeTime time.Duration) (string, bool) {
	if cache.Has(username) {
		// if cache has expired return
		if expiredCache(username, cacheLifeTime) {
			return "", false
		}

		// read from cache
		key, err := cache.Read(username)
		if err != nil {
			cache.Erase(username)
			return "", false
		}

		// read cached response
		return string(key), true
	}
	return "", false
}

func usersFromIAM(cfg *config.Config) ([]string, error) {
	var users []string
	sess := session.Must(session.NewSession())
	iamClient := iam.New(sess)
	for _, group := range cfg.Groups {
		groupInput := iam.GetGroupInput{GroupName: &group.Name}
		groupOutput, err := iamClient.GetGroup(&groupInput)
		if err != nil {
			return users, errors.WithMessage(err, "getting iam group")
		}
		for _, user := range groupOutput.Users {
			users = append(users, *user.UserName)
		}
	}
	return users, nil
}

func expiredCache(key string, cacheLifeTime time.Duration) bool {
	info, err := os.Stat(path.Join(CachePath, key))
	if err != nil {
		return false
	}
	return info.ModTime().Add(cacheLifeTime * time.Second).Before(time.Now())
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
