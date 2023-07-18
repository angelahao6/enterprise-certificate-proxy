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

// Package keychain contains functions for retrieving certificates from the Darwin Keychain.
package keychain

/*
#cgo CFLAGS: -mmacosx-version-min=10.12
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// Maps for translating from crypto.Hash to SecKeyAlgorithm.
// https://developer.apple.com/documentation/security/seckeyalgorithm
var (
	ecdsaAlgorithms = map[crypto.Hash]C.CFStringRef{
		crypto.SHA256: C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
		crypto.SHA384: C.kSecKeyAlgorithmECDSASignatureDigestX962SHA384,
		crypto.SHA512: C.kSecKeyAlgorithmECDSASignatureDigestX962SHA512,
	}
	rsaPKCS1v15Algorithms = map[crypto.Hash]C.CFStringRef{
		crypto.SHA256: C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256,
		crypto.SHA384: C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384,
		crypto.SHA512: C.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512,
	}
	rsaPSSAlgorithms = map[crypto.Hash]C.CFStringRef{
		crypto.SHA256: C.kSecKeyAlgorithmRSASignatureDigestPSSSHA256,
		crypto.SHA384: C.kSecKeyAlgorithmRSASignatureDigestPSSSHA384,
		crypto.SHA512: C.kSecKeyAlgorithmRSASignatureDigestPSSSHA512,
	}
)

// cfStringToString returns a Go string given a CFString.
func cfStringToString(cfStr C.CFStringRef) string {
	s := C.CFStringGetCStringPtr(cfStr, C.kCFStringEncodingUTF8)
	if s != nil {
		return C.GoString(s)
	}
	glyphLength := C.CFStringGetLength(cfStr) + 1
	utf8Length := C.CFStringGetMaximumSizeForEncoding(glyphLength, C.kCFStringEncodingUTF8)
	if s = (*C.char)(C.malloc(C.size_t(utf8Length))); s == nil {
		panic("unable to allocate memory")
	}
	defer C.free(unsafe.Pointer(s))
	if C.CFStringGetCString(cfStr, s, utf8Length, C.kCFStringEncodingUTF8) == 0 {
		panic("unable to convert cfStringref to string")
	}
	return C.GoString(s)
}

func cfRelease(x unsafe.Pointer) {
	C.CFRelease(C.CFTypeRef(x))
}

// cfError is an error type that owns a CFErrorRef, and obtains the error string
// by using CFErrorCopyDescription.
type cfError struct {
	e C.CFErrorRef
}

// cfErrorFromRef converts a C.CFErrorRef to a cfError, taking ownership of the
// reference and releasing when the value is finalized.
func cfErrorFromRef(cfErr C.CFErrorRef) *cfError {
	if cfErr == 0 {
		return nil
	}
	c := &cfError{e: cfErr}
	runtime.SetFinalizer(c, func(x interface{}) {
		C.CFRelease(C.CFTypeRef(x.(*cfError).e))
	})
	return c
}

func (e *cfError) Error() string {
	s := C.CFErrorCopyDescription(C.CFErrorRef(e.e))
	defer C.CFRelease(C.CFTypeRef(s))
	return cfStringToString(s)
}

// keychainError is an error type that is based on an OSStatus return code, and
// obtains the error string with SecCopyErrorMessageString.
type keychainError C.OSStatus

func (e keychainError) Error() string {
	s := C.SecCopyErrorMessageString(C.OSStatus(e), nil)
	defer C.CFRelease(C.CFTypeRef(s))
	return cfStringToString(s)
}

// cfDataToBytes turns a CFDataRef into a byte slice.
func cfDataToBytes(cfData C.CFDataRef) []byte {
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(cfData)), C.int(C.CFDataGetLength(cfData)))
}

// bytesToCFData turns a byte slice into a CFDataRef. Caller then "owns" the
// CFDataRef and must CFRelease the CFDataRef when done.
func bytesToCFData(buf []byte) C.CFDataRef {
	return C.CFDataCreate(C.kCFAllocatorDefault, (*C.UInt8)(unsafe.Pointer(&buf[0])), C.CFIndex(len(buf)))
}

// int32ToCFNumber turns an int32 into a CFNumberRef. Caller then "owns"
// the CFNumberRef and must CFRelease the CFNumberRef when done.
func int32ToCFNumber(n int32) C.CFNumberRef {
	return C.CFNumberCreate(C.kCFAllocatorDefault, C.kCFNumberSInt32Type, unsafe.Pointer(&n))
}

// Key is a wrapper around the Keychain reference that uses it to
// implement signing-related methods with Keychain functionality.
type Key struct {
	privateKeyRef C.SecKeyRef
	certs         []*x509.Certificate
	once          sync.Once
}

// newKey makes a new Key wrapper around the key reference,
// takes ownership of the reference, and sets up a finalizer to handle releasing
// the reference.
func newKey(privateKeyRef C.SecKeyRef, certs []*x509.Certificate) (*Key, error) {
	k := &Key{
		privateKeyRef: privateKeyRef,
		certs:         certs,
	}

	// This struct now owns the key reference. Retain now and release on
	// finalise in case the credential gets forgotten about.
	C.CFRetain(C.CFTypeRef(privateKeyRef))
	runtime.SetFinalizer(k, func(x interface{}) {
		x.(*Key).Close()
	})
	return k, nil
}

// CertificateChain returns the credential as a raw X509 cert chain. This
// contains the public key.
func (k *Key) CertificateChain() [][]byte {
	rv := make([][]byte, len(k.certs))
	for i, c := range k.certs {
		rv[i] = c.Raw
	}
	return rv
}

// Close releases resources held by the credential.
func (k *Key) Close() error {
	// Don't double-release references.
	k.once.Do(func() {
		C.CFRelease(C.CFTypeRef(k.privateKeyRef))
	})
	return nil
}

// Public returns the corresponding public key for this Key. Good
// thing we extracted it when we created it.
func (k *Key) Public() crypto.PublicKey {
	return k.certs[0].PublicKey
}

// Sign signs a message digest. Here, we pass off the signing to Keychain library.
func (k *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// Map the signing algorithm and hash function to a SecKeyAlgorithm constant.
	var algorithms map[crypto.Hash]C.CFStringRef
	switch pub := k.Public().(type) {
	case *ecdsa.PublicKey:
		algorithms = ecdsaAlgorithms
	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			algorithms = rsaPSSAlgorithms
			break
		}
		algorithms = rsaPKCS1v15Algorithms
	default:
		return nil, fmt.Errorf("unsupported algorithm %T", pub)
	}
	algorithm, ok := algorithms[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("unsupported hash function %T", opts.HashFunc())
	}

	// Copy input over into CF-land.
	cfDigest := bytesToCFData(digest)
	defer C.CFRelease(C.CFTypeRef(cfDigest))

	var cfErr C.CFErrorRef
	sig := C.SecKeyCreateSignature(C.SecKeyRef(k.privateKeyRef), algorithm, C.CFDataRef(cfDigest), &cfErr)
	if cfErr != 0 {
		return nil, cfErrorFromRef(cfErr)
	}
	defer C.CFRelease(C.CFTypeRef(sig))

	return cfDataToBytes(C.CFDataRef(sig)), nil
}

// Cred gets the first Credential (filtering on issuer) corresponding to
// available certificate and private key pairs (i.e. identities) available in
// the Keychain. This includes both the current login keychain for the user,
// and the system keychain.
func Cred(issuerCN string) (*Key, error) {
	leafSearch := C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 5, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	defer C.CFRelease(C.CFTypeRef(unsafe.Pointer(leafSearch)))
	// Get identities (certificate + private key pairs).
	C.CFDictionaryAddValue(leafSearch, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassIdentity))
	// Get identities that are signing capable.
	C.CFDictionaryAddValue(leafSearch, unsafe.Pointer(C.kSecAttrCanSign), unsafe.Pointer(C.kCFBooleanTrue))
	// For each identity, give us the reference to it.
	C.CFDictionaryAddValue(leafSearch, unsafe.Pointer(C.kSecReturnRef), unsafe.Pointer(C.kCFBooleanTrue))
	// Be sure to list out all the matches.
	C.CFDictionaryAddValue(leafSearch, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitAll))
	// Do the matching-item copy.
	var leafMatches C.CFTypeRef
	if errno := C.SecItemCopyMatching((C.CFDictionaryRef)(leafSearch), &leafMatches); errno != C.errSecSuccess {
		return nil, keychainError(errno)
	}
	defer C.CFRelease(leafMatches)
	signingIdents := C.CFArrayRef(leafMatches)
	// Dump the certs into golang x509 Certificates.
	var (
		leafIdent C.SecIdentityRef
		leaf      *x509.Certificate
	)
	// Find the first valid leaf whose issuer (CA) matches the name in filter.
	// Validation in identityToX509 covers Not Before, Not After and key alg.
	for i := 0; i < int(C.CFArrayGetCount(signingIdents)) && leaf == nil; i++ {
		identDict := C.CFArrayGetValueAtIndex(signingIdents, C.CFIndex(i))
		xc, err := identityToX509(C.SecIdentityRef(identDict))
		if err != nil {
			continue
		}
		if xc.Issuer.CommonName == issuerCN {
			leaf = xc
			leafIdent = C.SecIdentityRef(identDict)
		}
	}

	caSearch := C.CFDictionaryCreateMutable(C.kCFAllocatorDefault, 0, &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
	defer C.CFRelease(C.CFTypeRef(unsafe.Pointer(caSearch)))
	// Get identities (certificates).
	C.CFDictionaryAddValue(caSearch, unsafe.Pointer(C.kSecClass), unsafe.Pointer(C.kSecClassCertificate))
	// For each identity, give us the reference to it.
	C.CFDictionaryAddValue(caSearch, unsafe.Pointer(C.kSecReturnRef), unsafe.Pointer(C.kCFBooleanTrue))
	// Be sure to list out all the matches.
	C.CFDictionaryAddValue(caSearch, unsafe.Pointer(C.kSecMatchLimit), unsafe.Pointer(C.kSecMatchLimitAll))
	// Do the matching-item copy.
	var caMatches C.CFTypeRef
	if errno := C.SecItemCopyMatching((C.CFDictionaryRef)(caSearch), &caMatches); errno != C.errSecSuccess {
		return nil, keychainError(errno)
	}
	defer C.CFRelease(caMatches)
	certRefs := C.CFArrayRef(caMatches)
	// Validate and dump the certs into golang x509 Certificates.
	var allCerts []*x509.Certificate
	for i := 0; i < int(C.CFArrayGetCount(certRefs)); i++ {
		refDict := C.CFArrayGetValueAtIndex(certRefs, C.CFIndex(i))
		if xc, err := certRefToX509(C.SecCertificateRef(refDict)); err == nil {
			allCerts = append(allCerts, xc)
		}
	}

	// Build a certificate chain from leaf by matching prev.RawIssuer to
	// next.RawSubject across all valid certificates in the keychain.
	var (
		certs      []*x509.Certificate
		prev, next *x509.Certificate
	)
	for prev = leaf; prev != nil; prev, next = next, nil {
		certs = append(certs, prev)
		for _, xc := range allCerts {
			if certIn(xc, certs) {
				continue // finite chains only, mmmmkay.
			}
			if bytes.Equal(prev.RawIssuer, xc.RawSubject) && prev.CheckSignatureFrom(xc) == nil {
				// Prefer certificates with later expirations.
				if next == nil || xc.NotAfter.After(next.NotAfter) {
					next = xc
				}
			}
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no key found with issuer common name %q", issuerCN)
	}

	skr, err := identityToSecKeyRef(leafIdent)
	if err != nil {
		return nil, err
	}
	defer C.CFRelease(C.CFTypeRef(skr))
	return newKey(skr, certs)
}

// identityToX509 converts a single CFDictionary that contains the item ref and
// attribute dictionary into an x509.Certificate.
func identityToX509(ident C.SecIdentityRef) (*x509.Certificate, error) {
	var certRef C.SecCertificateRef
	if errno := C.SecIdentityCopyCertificate(ident, &certRef); errno != 0 {
		return nil, keychainError(errno)
	}
	defer C.CFRelease(C.CFTypeRef(certRef))

	return certRefToX509(certRef)
}

// certRefToX509 converts a single C.SecCertificateRef into an *x509.Certificate.
func certRefToX509(certRef C.SecCertificateRef) (*x509.Certificate, error) {
	// Export the PEM-encoded certificate to a CFDataRef.
	var certPEMData C.CFDataRef
	if errno := C.SecItemExport(C.CFTypeRef(certRef), C.kSecFormatUnknown, C.kSecItemPemArmour, nil, &certPEMData); errno != 0 {
		return nil, keychainError(errno)
	}
	defer C.CFRelease(C.CFTypeRef(certPEMData))
	certPEM := cfDataToBytes(certPEMData)

	// This part based on crypto/tls.
	var certDERBlock *pem.Block
	for {
		certDERBlock, certPEM = pem.Decode(certPEM)
		if certDERBlock == nil {
			return nil, fmt.Errorf("failed to parse certificate PEM data")
		}
		if certDERBlock.Type == "CERTIFICATE" {
			// found it
			break
		}
	}

	// Check the certificate is OK by the x509 library, and obtain the
	// public key algorithm (which I assume is the same as the private key
	// algorithm). This also filters out certs missing critical extensions.
	xc, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		return nil, err
	}
	switch xc.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("unsupported key type %T", xc.PublicKey)
	}

	// Check the certificate is valid
	if n := time.Now(); n.Before(xc.NotBefore) || n.After(xc.NotAfter) {
		return nil, fmt.Errorf("certificate not valid")
	}

	return xc, nil
}

// identityToSecKeyRef converts a single CFDictionary that contains the item ref and
// attribute dictionary into a SecKeyRef for its private key.
func identityToSecKeyRef(ident C.SecIdentityRef) (C.SecKeyRef, error) {
	// Get the private key (ref). Note that "Copy" in "CopyPrivateKey"
	// refers to "the create rule" of CoreFoundation memory management, and
	// does not actually copy the private key---it gives us a copy of the
	// reference that we now own.
	var ref C.SecKeyRef
	if errno := C.SecIdentityCopyPrivateKey(C.SecIdentityRef(ident), &ref); errno != 0 {
		return 0, keychainError(errno)
	}
	return ref, nil
}

func stringIn(s string, ss []string) bool {
	for _, s2 := range ss {
		if s == s2 {
			return true
		}
	}
	return false
}

func certIn(xc *x509.Certificate, xcs []*x509.Certificate) bool {
	for _, xc2 := range xcs {
		if xc.Equal(xc2) {
			return true
		}
	}
	return false
}

/*
Encrypt() function works to asymmetrically encrypt using a given public key
This version of Encrypt() will use the Go Crypto API encrypt function instead of SecKey
*/
func (k *Key) EncryptRSA(hashInput hash.Hash, random io.Reader, msg []byte) ([]byte, error) {
	pub := k.Public()
	var publicKey interface{} = pub
	rsaPubKey := publicKey.(rsa.PublicKey)
	return rsa.EncryptOAEP(hashInput, random, &rsaPubKey, msg, nil)
}

/*
Encrypt() function works to asymmetrically encrypt using a given public key
parameters: public key, desired algorithm to use, data to encryt
return value: CFDataRef since the SecKeyCreateEncryptedData() function returns that value, error
*/
func (k *Key) Encrypt(algorithm C.SecKeyAlgorithm, plaintext C.CFDataRef) (cfData C.CFDataRef, err error) {
	// choose the algorithm that suits the key's capabilities (?) certRefToX509()?
	// should also test if the algorithm works using kSecKeyOperationTypeEncrypt & SecKeyIsAlgorithmSupported() or certRefToX509()
	// peform a length test using SecKeyGetBlockSize
	// perform the encryption using SecKeyCreateEncryptedData()

	// Converting public key to type SecKeyRef
	// SecKeyRef, ok := public.(C.SecKeyRef)
	// if !ok {
	// 	return 0, fmt.Errorf("failed to convert public key to SecKeyRef, %v", SecKeyRef)
	// }
	pub := k.Public()
	var publicKey interface{} = pub
	SecKeyRef := publicKey.(C.SecKeyRef)
	cipherText, err := C.SecKeyCreateEncryptedData(SecKeyRef, algorithm, plaintext, nil)
	return cipherText, err
}

/*
Decrypt() function works to decrypt using a given private key
parameters: private key, desired algorithm to use, data to decrypt
return value: CFDataRef since the SecKeyCreateDecryptedData() function returns that value, error
*/
// func Decrypt() (cfData C.CFDataRef, err error) {

// }
