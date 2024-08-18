package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)
func GenerateECCKey() *ecdsa.PrivateKey {
	curve := elliptic.P521() // 选择曲线
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate private key: %v", err)
	}
	return privateKey
}


func CreateSelfSignedECCCertificate(key *ecdsa.PrivateKey) []byte {
	template := x509.Certificate{
		SerialNumber: big.NewInt(2024), // 序列号
		Subject: pkix.Name{
			Organization:  []string{"My Organization"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94107"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0), // 证书有效期1年

		// 可以添加更多的字段，如KeyUsage、ExtKeyUsage等
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// PEM编码证书
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return pemBytes
}

func main() {
	eccKey := GenerateECCKey()
	certBytes := CreateSelfSignedECCCertificate(eccKey)
	fmt.Printf("ECC Certificate:\n%s\n", certBytes)
}