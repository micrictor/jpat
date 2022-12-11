package config

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/golang-jwt/jwt"
	"gopkg.in/yaml.v2"
)

const DEFAULT_TTL = 60

type ServiceConfig struct {
	Port uint16 `yaml:"port"`
	Host string `yaml:"host"`
	Ttl  int64  `yaml:"ttl,omitempty"`
}

type JwtAlgorithm struct {
	GetKeyFunc func(config VerificationConfig) jwt.Keyfunc
}

var SUPPORTED_ALGOS = map[string]JwtAlgorithm{
	"rs256": {
		GetKeyFunc: func(config VerificationConfig) jwt.Keyfunc {
			return func(token *jwt.Token) (interface{}, error) {
				if config.PublicKeyFile == "" {
					return nil, fmt.Errorf("jwt algo rs256 (RSA with SHA256) requires publicKeyFile to be set")
				}
				if strings.ToLower(token.Method.Alg()) != "rs256" {
					return nil, fmt.Errorf("token uses algo %s, expected rs256", token.Method.Alg())
				}

				fileHandle, err := os.Open(config.PublicKeyFile)
				if err != nil {
					return nil, err
				}

				buf := new(bytes.Buffer)
				buf.ReadFrom(fileHandle)

				return buf.Bytes(), nil
			}
		},
	},
	"hs256": {
		GetKeyFunc: func(config VerificationConfig) jwt.Keyfunc {
			return func(token *jwt.Token) (interface{}, error) {
				if config.Secret == "" {
					return nil, fmt.Errorf("jwt algo hs256 (HMAC SHA256) requires secret to be set")
				}
				if strings.ToLower(token.Method.Alg()) != "hs256" {
					return nil, fmt.Errorf("token uses algo %s, expected hs256", token.Method.Alg())
				}

				return []byte(config.Secret), nil
			}
		},
	},
}

type VerificationConfig struct {
	Algo          string `yaml:"algo"`
	PublicKeyFile string `yaml:"publicKeyFile,omitempty"`
	Secret        string `yaml:"secret,omitempty"`
}

type MarshalledConfig struct {
	Service      ServiceConfig      `yaml:"service"`
	Verification VerificationConfig `yaml:"verification"`
}

type AppConfig struct {
	Service ServiceConfig
	Keyfunc jwt.Keyfunc
}

var config *AppConfig

func getConfig(data []byte) (config *AppConfig, err error) {
	var tempConfig = new(MarshalledConfig)

	err = yaml.Unmarshal(data, &tempConfig)
	if err != nil {
		log.Panicf("failed to unmarshal config: %s", err.Error())
	}

	algo, ok := SUPPORTED_ALGOS[strings.ToLower(tempConfig.Verification.Algo)]
	if !ok {
		log.Panicf("unsupported algorithm %s", tempConfig.Verification.Algo)
	}

	if tempConfig.Service.Ttl == 0 {
		tempConfig.Service.Ttl = DEFAULT_TTL
	}

	return &AppConfig{
		Service: tempConfig.Service,
		Keyfunc: algo.GetKeyFunc(tempConfig.Verification),
	}, nil
}

func New(reader io.Reader) *AppConfig {
	if config != nil {
		return config
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(reader)
	data := buf.Bytes()

	result, err := getConfig(data)
	if err != nil {
		log.Fatalf("Failed to parse config: %s", err.Error())
	}

	if result.Service.Host == "" || result.Service.Port == 0 || result.Service.Ttl == 0 {
		log.Fatalf("Config service definition is invalid: %v", result.Service)
	}

	config = result
	return config
}
