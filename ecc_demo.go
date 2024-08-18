package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"io/ioutil"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
	"os"
)
func GenerateECCKey() *ecdsa.PrivateKey {
	curve := elliptic.P521() // 选择曲线
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate private key: %v", err)
	}
		// 将私钥编码为 DER 格式
	derBytes ,_:= x509.MarshalECPrivateKey(privateKey)

	// 创建 PEM 块
	pemBlock := pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}

	// 创建文件并写入 PEM 块
	fileName := "ecc.pem"
	file, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// 编码 PEM 并写入文件
	err = pem.Encode(file, &pemBlock)
	if err != nil {
		panic(err)
	}

	// 输出保存成功的消息
	println("Private key saved to:", fileName)
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
	ioutil.WriteFile("ecc.crt", certBytes, 0644)
}