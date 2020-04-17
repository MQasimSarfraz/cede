package config

import (
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type Config struct {
	AllowedDomains []string `yaml:"allowedDomains"`
	ExternalUsers  []string `yaml:"externalUsers"`
	Groups         []Group  `yaml:"groups"`
}

type Group struct {
	Name        string `yaml:"name"`
	IsSuperuser bool   `yaml:"superuser"`
}

func Read(path string) (*Config, error) {
	configFile, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.WithMessage(err, "reading config")
	}

	config := &Config{}
	err = yaml.Unmarshal(configFile, config)
	if err != nil {
		return nil, errors.WithMessage(err, "unmarshalling config")
	}
	return config, nil
}

func GetOrDefaultPath() string {
	path := os.Getenv("CEDE_CONFIG_PATH")
	if path != "" {
		return path
	}
	return "/etc/cede/cede.conf"
}
