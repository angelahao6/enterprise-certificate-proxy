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

// signer.go is a net/rpc server that listens on stdin/stdout, exposing
// mock methods for testing client.go.
package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/rpc"
	"os"
	"time"
)

// SignArgs encapsulate the parameters for the Sign method.
type SignArgs struct {
	Digest []byte
	Opts   crypto.SignerOpts
}

type EncryptArgs struct {
	Plaintext []byte
}

type DecryptArgs struct {
	Ciphertext []byte
}

// EnterpriseCertSigner exports RPC methods for signing.
type EnterpriseCertSigner struct {
	cert *tls.Certificate
}

// Connection wraps a pair of unidirectional streams as an io.ReadWriteCloser.
type Connection struct {
	io.ReadCloser
	io.WriteCloser
}

// Close closes c's underlying ReadCloser and WriteCloser.
func (c *Connection) Close() error {
	rerr := c.ReadCloser.Close()
	werr := c.WriteCloser.Close()
	if rerr != nil {
		return rerr
	}
	return werr
}

// CertificateChain returns the credential as a raw X509 cert chain. This
// contains the public key.
func (k *EnterpriseCertSigner) CertificateChain(ignored struct{}, certificateChain *[][]byte) error {
	*certificateChain = k.cert.Certificate
	return nil
}

// Public returns the first public key for this Key, in ASN.1 DER form.
func (k *EnterpriseCertSigner) Public(ignored struct{}, publicKey *[]byte) (err error) {
	if len(k.cert.Certificate) == 0 {
		return nil
	}
	cert, err := x509.ParseCertificate(k.cert.Certificate[0])
	if err != nil {
		return err
	}
	*publicKey, err = x509.MarshalPKIXPublicKey(cert.PublicKey)
	return err
}

// Sign signs a message digest.
func (k *EnterpriseCertSigner) Sign(args SignArgs, resp *[]byte) (err error) {
	*resp = args.Digest
	return nil
}

func (k *EnterpriseCertSigner) Encrypt(args EncryptArgs, plaintext *[]byte) (err error) {
	*plaintext = args.Plaintext
	return nil
}

func (k *EnterpriseCertSigner) Decrypt(args DecryptArgs, ciphertext *[]byte) (err error) {
	*ciphertext = args.Ciphertext
	return nil
}

func main() {
	enterpriseCertSigner := new(EnterpriseCertSigner)

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatalf("Error reading certificate: %v", err)
	}
	cert, _ := tls.X509KeyPair(data, data)

	enterpriseCertSigner.cert = &cert

	if err := rpc.Register(enterpriseCertSigner); err != nil {
		log.Fatalf("Error registering net/rpc: %v", err)
	}

	// If the parent process dies, we should exit.
	// We can detect this by periodically checking if the PID of the parent
	// process is 1 (https://stackoverflow.com/a/2035683).
	go func() {
		for {
			if os.Getppid() == 1 {
				log.Fatalln("Parent process died, exiting...")
			}
			time.Sleep(time.Second)
		}
	}()

	rpc.ServeConn(&Connection{os.Stdin, os.Stdout})
}
