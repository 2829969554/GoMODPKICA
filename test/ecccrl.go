package main  
  
import (  
    "fmt"
    "log"
    "io/ioutil"
    "crypto/rand" 
    "crypto/x509"
    "time"
    "crypto/x509/pkix"
    "encoding/asn1"
    "math/big" 
    "encoding/pem" 
    "path/filepath"
    "os"

)  
  
func main() {
    ex, _ := os.Executable() 
    thisFILE:= filepath.Dir(ex)  
    fmt.Println(thisFILE)
    ecccrtfile:=thisFILE+"\\ecc.crt"
    eccpemfile:=thisFILE+"\\ecc.pem"
    ecccrlfile:=thisFILE+"\\ecc.crl"
    ecccrt,err:=ioutil.ReadFile(ecccrtfile)
    if err != nil {
        log.Fatal(err)
    }
    eccpem,err2:=ioutil.ReadFile(eccpemfile)
    if err2 != nil {
        log.Fatal(err2)
    }
    fmt.Println("ECC OK")

    ecckeyder, _ := pem.Decode(eccpem) 
    ecckey,err3:= x509.ParseECPrivateKey(ecckeyder.Bytes)  
    if err3 != nil {
        log.Fatal(err3)
    }
    fmt.Println(ecccrt)
    fmt.Println("ECCKEY YES")
    MODCERTLIST := []pkix.RevokedCertificate{}  
                 revokedCert := pkix.RevokedCertificate{  
                     SerialNumber:   big.NewInt(int64(2024)),  
                     RevocationTime: time.Now().UTC().Add(-24*time.Hour),  
                     Extensions: []pkix.Extension{  
                         {  
                         Id: asn1.ObjectIdentifier{2, 5, 29, 21},  
                         Critical: false,  
                         Value: []byte{0x0A, 0x01, byte(2)},  
                         },  
                     },  
                 }  
  

        MODCERTLIST = append(MODCERTLIST, revokedCert) 


     ecccrtder, _ := pem.Decode(ecccrt)  
      if ecccrtder == nil || ecccrtder.Type != "CERTIFICATE"{  
            log.Fatal("无效的PEM证书")  
         }  
    ecccert, err5 := x509.ParseCertificate(ecccrtder.Bytes) 
    if err5 != nil {
        log.Fatal(err5)
    }
    ecccrl,err4:=ecccert.CreateCRL(rand.Reader,ecckey,MODCERTLIST,time.Now().UTC().Add(-24*time.Hour), time.Now().UTC().Add(24*time.Hour))
    if err4 != nil {
        log.Fatal(err4)
    }
    fmt.Println(ecccrl)
    err6 := ioutil.WriteFile(ecccrlfile, ecccrl, 0644)
    if err6 != nil {
        log.Fatal(err6)
    }
    fmt.Println("ECC END")
}