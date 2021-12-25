package config

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const YAML_HEADER = "---\n"

const SERVICE_CONFIG = `
  service:
    host: 127.0.0.1
    port: 1337
    ttl: %d
`
const VERIFICATION_CONFIG = `
  verification:
    algo: %s
    publicKeyFile: %s
    secret: %s
`

func TestNew(t *testing.T) {
	testCases := []struct {
		algo          string
		publicKeyFile string
		secret        string
	}{
		{"rs256", "/a/file", ""},
		{"hs256", "", "secretstring"},
	}
	for _, tc := range testCases {
		inputBuffer := new(bytes.Buffer)
		var builder strings.Builder
		builder.WriteString(YAML_HEADER)
		builder.WriteString(fmt.Sprintf(SERVICE_CONFIG, 60))
		builder.WriteString(fmt.Sprintf(VERIFICATION_CONFIG, tc.algo, tc.publicKeyFile, tc.secret))
		inputBuffer.WriteString(builder.String())

		testConfig := New(inputBuffer)

		expectedService := ServiceConfig{
			Host: "127.0.0.1",
			Port: 1337,
			Ttl:  60,
		}
		if testConfig.Service != expectedService {
			t.Errorf("Service %v does not match expected service %v", testConfig.Service, expectedService)
		}

		_, ok := SUPPORTED_ALGOS[tc.algo]
		if !ok {
			t.Errorf("algo %s not supported", tc.algo)
		}

		if testConfig.Keyfunc == nil || reflect.TypeOf(testConfig.Keyfunc).Kind() != reflect.Func {
			t.Errorf("keyfunc is not set or is not callable")
		}

		config = nil
	}
}

func TestNewUnsupportedAlgo(t *testing.T) {
	testCases := []struct {
		algo string
	}{
		{"notarealalgo"},
	}
	for _, tc := range testCases {
		inputBuffer := new(bytes.Buffer)
		var builder strings.Builder
		builder.WriteString(YAML_HEADER)
		builder.WriteString(fmt.Sprintf(SERVICE_CONFIG, 60))
		builder.WriteString(fmt.Sprintf(VERIFICATION_CONFIG, tc.algo, "", ""))
		inputBuffer.WriteString(builder.String())

		defer func() {
			if r := recover(); r == nil {
				t.Errorf("The code did not panic")
			}
		}()
		_ = New(inputBuffer)
	}
}

func TestNewSingleton(t *testing.T) {
	testCases := []struct {
		algo          string
		publicKeyFile string
		secret        string
	}{
		{"rs256", "/a/file", ""},
		{"notarealalgo", "badconfig", "badconfig"},
	}
	var configList []*AppConfig
	for _, tc := range testCases {
		inputBuffer := new(bytes.Buffer)
		var builder strings.Builder
		builder.WriteString(YAML_HEADER)
		builder.WriteString(fmt.Sprintf(SERVICE_CONFIG, 60))
		builder.WriteString(fmt.Sprintf(VERIFICATION_CONFIG, tc.algo, tc.publicKeyFile, tc.secret))
		inputBuffer.WriteString(builder.String())
		currentConfig := New(inputBuffer)
		configList = append(configList, currentConfig)
	}

	if configList[0] != configList[1] {
		t.Errorf("Configs do not match")
	}
}
