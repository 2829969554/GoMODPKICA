package main

import (
    "fmt"
    "log"
    "crypto/rand"
    "tjfoc/gmsm/x509"
    //oldx509 "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    //"encoding/asn1"
    "math/big"
    "time"
    "io/ioutil"
    "tjfoc/gmsm/sm2"
    "net"
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
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().AddDate(1, 0, 0), // 证书有效期1年
        DNSNames:[]string{"anqikeji.picp.net","localhost",},
        IPAddresses:[]net.IP{net.ParseIP("127.0.0.1"),},
        IsCA:false,
        BasicConstraintsValid: true,
        //ExtKeyUsage:[]x509.ExtKeyUsage{1,2,3,4,5,6,7,},
        KeyUsage:1|4|8|16,
       // PolicyIdentifiers: []asn1.ObjectIdentifier{{2,23,140,1,3},{2,23,140,1,1},}, 
        SignatureAlgorithm:x509.SM2WithSM3,
      //  AuthorityKeyId:1,
      //  SubjectKeyId:1,
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