// Copyright 2022 Google LLC.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package util provides helper functions for the client.
package util

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

const configFileName = "certificate_config.json"

// EnterpriseCertificateConfig contains parameters for initializing signer.
type EnterpriseCertificateConfig struct {
	Libs Libs `json:"libs"`
}

// Libs specifies the locations of helper libraries.
type Libs struct {
	ECP string `json:"ecp"`
}

// ErrConfigUnavailable is a sentinel error that indicates ECP config is unavailable,
// possibly due to entire config missing or missing binary path.
var ErrConfigUnavailable = errors.New("Config is unavailable")

/* UPDATED FUNCTION */
// LoadSignerBinaryPath retrieves the path of the signer binary from the config file.
func LoadSignerBinaryPath(configFilePath string) (path string, err error) {
	jsonFile, err := os.Open(configFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrConfigUnavailable
		}
		return "", err
	}

	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		return "", err
	}
	var config EnterpriseCertificateConfig
	err = json.Unmarshal(byteValue, &config)
	if err != nil {
		return "", err
	}
	signerBinaryPath := config.Libs.ECP
	if signerBinaryPath == "" {
		return "", ErrConfigUnavailable
	}
	// Checking for ~ & HOME variables to represent home directory
	if strings.Contains(signerBinaryPath, "~") || strings.Contains(signerBinaryPath, "HOME") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", ErrConfigUnavailable
		}
		// Updating signerBinaryPath to substitute "~" or "HOME" with the home directory + the rest of the path
		if strings.Contains(signerBinaryPath, "~") {
			signerBinaryPath = homeDir + strings.TrimLeft(signerBinaryPath, "~")
		}
		if strings.Contains(signerBinaryPath, "HOME") {
			signerBinaryPath = homeDir + strings.TrimLeft(signerBinaryPath, "HOME")
		}
		return signerBinaryPath, nil
	}
	return signerBinaryPath, nil
}

/* ORIGINAL FUNCTION */
// // LoadSignerBinaryPath retrieves the path of the signer binary from the config file.
// func LoadSignerBinaryPath(configFilePath string) (path string, err error) {
// 	jsonFile, err := os.Open(configFilePath)
// 	if err != nil {
// 		if errors.Is(err, os.ErrNotExist) {
// 			return "", ErrConfigUnavailable
// 		}
// 		return "", err
// 	}

// 	byteValue, err := io.ReadAll(jsonFile)
// 	if err != nil {
// 		return "", err
// 	}
// 	var config EnterpriseCertificateConfig
// 	err = json.Unmarshal(byteValue, &config)
// 	if err != nil {
// 		return "", err
// 	}
// 	signerBinaryPath := config.Libs.ECP
// 	if signerBinaryPath == "" {
// 		return "", ErrConfigUnavailable
// 	}
// 	return signerBinaryPath, nil
// }

func guessHomeDir() string {
	// Prefer $HOME over user.Current due to glibc bug: golang.org/issue/13470
	if v := os.Getenv("HOME"); v != "" {
		return v
	}
	// Else, fall back to user.Current:
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

func getDefaultConfigFileDirectory() (directory string) {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("APPDATA"), "gcloud")
	}
	return filepath.Join(guessHomeDir(), ".config/gcloud")
}

// GetDefaultConfigFilePath returns the default path of the enterprise certificate config file created by gCloud.
func GetDefaultConfigFilePath() (path string) {
	return filepath.Join(getDefaultConfigFileDirectory(), configFileName)
}
