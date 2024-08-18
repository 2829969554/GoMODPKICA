package main

import (
    "fmt"
    "log"
    "crypto/rand"
    "tjfoc/gmsm/x509"
    //oldx509 "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "time"
    "io/ioutil"
    "tjfoc/gmsm/sm2"
)


func GenerateSM2Key() *sm2.PrivateKey {
    privateKey, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        log.Fatalf("failed to generate private key: %v", err)
    }
        // 将SM2私钥编码为DER格式
    data,err:=x509.WritePrivateKeyToPem(privateKey,nil)

    if err != nil {
        panic(err)
    }else{
        ioutil.WriteFile("sm2.pem", data, 0644)
    }
    

    return privateKey
}

func CreateSelfSignedSM2Certificate(key *sm2.PrivateKey) []byte {
    template := x509.Certificate{
        SerialNumber: big.NewInt(2024), // 序列号
        Subject: pkix.Name{
            Organization:  []string{"My Organization"},
            Country:       []string{"US"},
            Province:      []string{"CA"},
            Locality:      []string{"San Francisco"},
            StreetAddress: []string{"Golden Gate Bridge"},
            PostalCode:    []string{"94107"},
            EVCT: []string{"CN"},
            EVCITY: []string{"BEI JING"},
            EVTYPE: []string{"Private Organization"},
            EMAIL:[]string{"2829969554@qq.com"},
            SerialNumber:"123456789",
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().AddDate(1, 0, 0), // 证书有效期1年

        // 可以添加更多的字段，如KeyUsage、ExtKeyUsage等
    }

    derBytes, err := x509.CreateCertificate(&template, &template, &key.PublicKey, key)
    if err != nil {
        log.Fatalf("Failed to create certificate: %v", err)
    }

    // PEM编码证书
    pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
    return pemBytes
}

func main() {
    eccKey := GenerateSM2Key()
    certBytes := CreateSelfSignedSM2Certificate(eccKey)
    fmt.Printf("SM2 Certificate:\n%s\n", certBytes)
    ioutil.WriteFile("sm2.crt", certBytes, 0644)
}