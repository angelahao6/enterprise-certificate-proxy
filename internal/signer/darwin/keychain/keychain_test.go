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

//go:build darwin && cgo
// +build darwin,cgo

package keychain

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"unsafe"

	"fmt"
)

func TestKeychainError(t *testing.T) {
	tests := []struct {
		e    keychainError
		want string
	}{
		{e: keychainError(0), want: "No error."},
		{e: keychainError(-4), want: "Function or operation not implemented."},
	}

	for i, test := range tests {
		if got := test.e.Error(); got != test.want {
			t.Errorf("test %d: %#v.Error() = %q, want %q", i, test.e, got, test.want)
		}
	}
}

func TestBytesToCFDataRoundTrip(t *testing.T) {
	want := []byte("an arbitrary and yet coherent byte slice!")
	d := bytesToCFData(want)
	defer cfRelease(unsafe.Pointer(d))
	if got := cfDataToBytes(d); !bytes.Equal(got, want) {
		t.Errorf("bytesToCFData -> cfDataToBytes\ngot  %x\nwant %x", got, want)
	}
}

func TestEncryptRSA(t *testing.T) {
	hashFunc := sha256.New()
	rng := rand.Reader
	key, errCred := Cred("enterprise_v1_corp_client-signer-0-2018-07-03T10:55:10-07:00 K:1, 2:BXmhnePmGN4:0:18")
	if errCred != nil {
		t.Errorf("Cred error: %q", errCred)
		return
	}
	message := []byte("Plain text to encrypt")

	_, errEncrypt := key.EncryptRSA(hashFunc, rng, message)
	if errEncrypt != nil {
		t.Errorf("Encrypt error: %q", errEncrypt)
		return
	}
	fmt.Println("Encrypted")
}

func BenchmarkEncryptRSA(b *testing.B) {
	hashFunc := sha256.New()
	rng := rand.Reader
	key, errCred := Cred("enterprise_v1_corp_client-signer-0-2018-07-03T10:55:10-07:00 K:1, 2:BXmhnePmGN4:0:18")
	if errCred != nil {
		b.Errorf("Cred error: %q", errCred)
		return
	}
	message := []byte("Plain text to encrypt")

    for i := 0; i < b.N; i++ {
        _, errEncrypt := key.EncryptRSA(hashFunc, rng, message)
        if errEncrypt != nil {
            b.Errorf("Encrypt error: %q", errEncrypt)
            return
        }
    }
}

func TestSecKeyEncrypt(t *testing.T) {
	key, err := Cred("enterprise_v1_corp_client-signer-0-2018-07-03T10:55:10-07:00 K:1, 2:BXmhnePmGN4:0:18")
	if err != nil {
		t.Errorf("Cred error: %q", err)
		return
	}
	key.PrintSupportedAlgorithms()
	hashFunc := crypto.Hash(crypto.SHA256)
	rsaAlgor := rawRSA[hashFunc]

	buffer := []byte("Plain text to encrypt")
	dataRef := bytesToCFData(buffer)

	fmt.Print("Test")
	msg, _ := key.Encrypt(rsaAlgor, dataRef)
	// if errEncrypt != nil {
	// 	t.Errorf("Encrypt error: %v", errEncrypt)
	// 	return
	// }
	byteSlice := cfDataToBytes(msg)
	fmt.Printf("Encrypted %+v\n", byteSlice)
}

func TestDecryptSecKey(t *testing.T) {
	key, err := Cred("enterprise_v1_corp_client-signer-0-2018-07-03T10:55:10-07:00 K:1, 2:BXmhnePmGN4:0:18")
	if err != nil {
		t.Errorf("Cred error: %q", err)
		return
	}
	hashFunc := crypto.Hash(crypto.SHA256)
	rsaAlgor := rawRSA[hashFunc]

	buffer := []byte("Plain text to encrypt")
	dataRef := bytesToCFData(buffer)

	fmt.Print("Test")
	msg, _ := key.Encrypt(rsaAlgor, dataRef)
	// if errEncrypt != nil {
	// 	t.Errorf("Encrypt error: %v", errEncrypt)
	// 	return
	// }
	// Decrypting
	plaintext, errDecrypt := key.Decrypt(msg)
	if errDecrypt != nil {
		t.Errorf("Encrypt error: %q", errDecrypt)
		return
	}
	byteSlice := (cfDataToBytes(plaintext))
	readable := string(byteSlice)
	fmt.Println("Decrypted successfully:", readable)
}

// func TestDecryptOAEP(t *testing.T) {
// 	hashFunc := sha256.New()
// 	rng := rand.Reader
// 	key, errCred := Cred("enterprise_v1_corp_client-signer-0-2018-07-03T10:55:10-07:00 K:1, 2:BXmhnePmGN4:0:18")
// 	if errCred != nil {
// 		t.Errorf("Cred error: %q", errCred)
// 		return
// 	}
// 	message := []byte("Plain text to encrypt")

// 	cipherText, errEncrypt := key.EncryptRSA(hashFunc, rng, message)
// 	if errEncrypt != nil {
// 		t.Errorf("Encrypt error: %q", errEncrypt)
// 		return
// 	}
// 	fmt.Println("Encrypted message: ", cipherText)

// 	// Decrypting
// 	// Converting hash algorithm into encryption algorithm
// 	// var hashIn interface{} = hashFunc
// 	// cryptoHash := hashIn.(crypto.Hash)
// 	// rsaAlgor := rsaPKCS1v15Algorithms[cryptoHash]

// 	text2Decrypt := bytesToCFData(cipherText)

// 	plaintext, errDecrypt := key.Decrypt(text2Decrypt)
// 	if errDecrypt != nil {
// 		t.Errorf("Encrypt error: %q", errDecrypt)
// 		return
// 	}
// 	byteSlice := (cfDataToBytes(plaintext))
// 	readable := string(byteSlice)
// 	fmt.Println("Decrypted message:", readable)
// }
