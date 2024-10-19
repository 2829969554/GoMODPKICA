package main  
  
import (  
    "fmt"
    "log"
    "io/ioutil"
    "crypto/rand" 
    "tjfoc/gmsm/x509"
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
    smcrtfile:=thisFILE+"/sm2.crt"
    smpemfile:=thisFILE+"/sm2.pem"
    smcrlfile:=thisFILE+"/sm2.crl"
    smcrt,err:=ioutil.ReadFile(smcrtfile)
    if err != nil {
        log.Fatal(err)
    }
    smpem,err2:=ioutil.ReadFile(smpemfile)
    if err2 != nil {
        log.Fatal(err2)
    }
    fmt.Println("SM2 OK")

    smkey,err3:=x509.ReadPrivateKeyFromPem(smpem,nil)
    if err3 != nil {
        log.Fatal(err3)
    }
    fmt.Println(smcrt)
    fmt.Println("SMKEY YES")
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
 
    smcert, err5 := x509.ParseCertificate(smcrt)

     smcrtder, _ := pem.Decode(smcrt)  
      if smcrtder == nil || smcrtder.Type != "CERTIFICATE"{  
            log.Print("无效的PEM证书")  
             
         }else{
            smcert, err5 = x509.ParseCertificate(smcrtder.Bytes) 
         }  
    
    if err5 != nil {
        log.Fatal(err5)
    }
    var crllist x509.RevocationList
    crllist.RevokedCertificates=MODCERTLIST
    crllist.Number=big.NewInt(1)
    crllist.ThisUpdate=time.Now()
    crllist.NextUpdate=time.Now().Add(24*time.Hour)
    smcrl,err4:=x509.CreateRevocationList(rand.Reader,&crllist,smcert,smkey)
    if err4 != nil {
        log.Fatal(err4)
    }
    fmt.Println(smcrl)
    err6 := ioutil.WriteFile(smcrlfile, smcrl, 0644)
    if err6 != nil {
        log.Fatal(err6)
    }
    fmt.Println("SM END")
}
