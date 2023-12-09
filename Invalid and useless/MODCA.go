package main  
  //http://127.0.0.1:8081/root.crt
import (  
 "crypto/rand"  
 "crypto/rsa"  
 "crypto/x509"  
 "crypto/x509/pkix"  
 "encoding/pem"  
 "fmt"  
 "math/big"  
 "os"  
 "time"
 "encoding/hex"
 "net"   
 "net/url" 
 "encoding/asn1"
)  
  
func main() {  
 // 生成RSA密钥对  
 privateKey, err := rsa.GenerateKey(rand.Reader, 1024)  

 if err != nil {  
    fmt.Println("密钥对生成失败：", err)  
    return  
 }  
 //MOD***************************
 //保存公钥
 savePrivateKey(privateKey, "private.key")  
 // 将公钥保存到文件（公钥.pem）  
 savePublicKey(privateKey, "public.key") 

 //MOD颁发者密钥
 priid,err:=hex.DecodeString("A1")
 subid,err:=hex.DecodeString("A1")
 subid2,err:=hex.DecodeString("A2")
 //MOD证书策略 
 MODPolicyIdentifiers := []asn1.ObjectIdentifier{
    asn1.ObjectIdentifier{2,23,140,1,1},{2,16,840,1,114412,2,1},
 }  

 //MOD添加其他增强型密钥用法 补充
 MODUnknownExtKeyUsage := []asn1.ObjectIdentifier{
    asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,1},

 } 


//fmt.Println("id：", x509.ExtKeyUsageAny,x509.ExtKeyUsageServerAuth,x509.ExtKeyUsageClientAuth)  
 //MODPolicyIdentifiers = append(MODPolicyIdentifiers, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 4})  

//MOD***********************
 // 创建证书模板  
 template := x509.Certificate{  
     SerialNumber: big.NewInt(1),  
     Subject: pkix.Name{  
     CommonName:   "aaa", // 证书主题名称  
     Organization: []string{"O"}, // 组织名称  
     Country:      []string{"CN"},
     SerialNumber:         "123", 
     OrganizationalUnit:   []string{"OU"},
     Locality:        []string{"L"},
     Province:        []string{"P"},
     StreetAddress:   []string{"ST"},
     PostalCode:      []string{"666666"},
 },  
     NotBefore: time.Now(), // 证书生效时间  
     NotAfter:  time.Now().AddDate(1, 0, 0), // 证书过期时间，这里设置为1年后的今天  
     

  //1    x509.KeyUsageDigitalSignature
  //2    x509.KeyUsageContentCommitment
  //4    x509.KeyUsageKeyEncipherment
  //8    x509.KeyUsageDataEncipherment
  //16   x509.KeyUsageKeyAgreement
  //32   x509.KeyUsageCertSign
  //64   x509.KeyUsageCRLSign
  //128  x509.KeyUsageEncipherOnly
  //256  x509.KeyUsageDecipherOnly

  KeyUsage:1|2|4|8|16|32|64|128|256, // 密钥用途，用于加密和数字签名  
     
//增强型密钥用法
//0    ExtKeyUsageAny
//1    ExtKeyUsageServerAuth
//2    ExtKeyUsageClientAuth
//3    ExtKeyUsageCodeSigning
//4    ExtKeyUsageEmailProtection
//5    ExtKeyUsageIPSECEndSystem
//6    ExtKeyUsageIPSECTunnel
//7    ExtKeyUsageIPSECUser
//8    ExtKeyUsageTimeStamping
//9    ExtKeyUsageOCSPSigning
//10   ExtKeyUsageMicrosoftServerGatedCrypto
//11   ExtKeyUsageNetscapeServerGatedCrypto
//12   ExtKeyUsageMicrosoftCommercialCodeSigning
//13   ExtKeyUsageMicrosoftKernelCodeSigning

     ExtKeyUsage: []x509.ExtKeyUsage{    // 扩展密钥用途，用于服务器身份验证和客户端认证等  
     0,1,2,3,4,5,6,7,8,9,10,11,12,13,
 },

//MOD 重点 补充其他增强型密钥用法  例如{2.2.4.4},{1.2.3.4}
UnknownExtKeyUsage:MODUnknownExtKeyUsage,


//签名算法
    //RSA
    //3   SHA1WithRSA
    //4   SHA256WithRSA
    //5   SHA384WithRSA
    //6   SHA512WithRSA
    //强RSA签名
    //13  SHA256WithRSAPSS
    //14  SHA384WithRSAPSS
    //15  SHA512WithRSAPSS
    //ECDSA
    //9   ECDSAWithSHA1
    //10  ECDSAWithSHA256
    //11  ECDSAWithSHA384
    //12  ECDSAWithSHA512
    SignatureAlgorithm:14, 

    BasicConstraintsValid: true,
    IsCA: true,
    // 非CA证书的基本约束有效，用于限制证书的使用范围 
    MaxPathLen:3,
    //证书链最大层次


    //使用者密钥标识符和颁发者密钥标识符
    AuthorityKeyId:priid,
    SubjectKeyId:subid,

    //颁发者信息访问
    OCSPServer:[]string{"http://ocsp.dcocsp.cn"},
    IssuingCertificateURL:[]string{"http://127.0.0.1:8081/root.crt"},
    CRLDistributionPoints:[]string{"http://127.0.0.1:8081/root.crt"},
    //使用者可选名称
    DNSNames:[]string{"dns.com"},
    EmailAddresses:[]string{"qq@dns.com"},
    IPAddresses:[]net.IP{net.ParseIP("192.168.0.1")},
    URIs :[]*url.URL{  
     {Scheme: "http", Host: "aaa.com"},  
     {Scheme: "https", Host: "bbb.com"},  
     {Scheme: "ftp", Host: "ccc.org"},  
     }, 

    PolicyIdentifiers:MODPolicyIdentifiers,
    //名称限制严格 名称约束
    /*
    PermittedDNSDomainsCritical:false,
    PermittedDNSDomains:[]string{"q1.com"},
    ExcludedDNSDomains:[]string{"q2.com"},
    */
}  





 // 创建下级CA证书模板  
 caTemplate := x509.Certificate{  
 SerialNumber: big.NewInt(2),  
 Subject: pkix.Name{  
 CommonName:   "ca.example.com", // CA证书主题名称  
 Organization: []string{"Example Org"}, // 组织名称  
 },  
 NotBefore: time.Now(),  
 NotAfter:  time.Now().AddDate(1, 0, 0), // 有效期为1年  
 KeyUsage:  1|2|4|8|16,  
 ExtKeyUsage: []x509.ExtKeyUsage{  
 1,2,3,  
 },  
 BasicConstraintsValid: true, // 设置CA证书的基本约束条件为有效，表示该证书是一个CA证书  
 IsCA:false,
 SubjectKeyId:subid2,
 PolicyIdentifiers:MODPolicyIdentifiers,
    IssuingCertificateURL:[]string{"http://127.0.0.1:8081/root.crt"},
    CRLDistributionPoints:[]string{"http://127.0.0.1:8081/root.crl"},
 }






 // 使用证书模板和RSA密钥对生成证书  
 rootderBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)  
 if err != nil {  
 fmt.Println("ROOT证书生成失败：", err)  
 return  
 }  

 caderBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &template, &privateKey.PublicKey, privateKey)  
 if err != nil {  
 fmt.Println("CA证书生成失败：", err)  
 return  
 } 

 // 将证书保存到文件  
 certOut, err := os.Create("root.crt")  
 if err != nil {  
 fmt.Println("ROOT无法创建证书文件：", err)  
 return  
 }  
 pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: rootderBytes})  
 certOut.Close()  
 fmt.Println("ROOT证书生成成功！")  

  // 将证书保存到文件  
 certOut2, err := os.Create("ca.crt")  
 if err != nil {  
 fmt.Println("ca无法创建证书文件：", err)  
 return  
 }  
 pem.Encode(certOut2, &pem.Block{Type: "CERTIFICATE", Bytes: caderBytes})  
 certOut2.Close()  
 fmt.Println("ca证书生成成功！")  


 
}


// 保存私钥到文件  
func savePrivateKey(privateKey *rsa.PrivateKey, filename string) error {  
 keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)  
 pemBlock := &pem.Block{  
 Type:  "RSA PRIVATE KEY",  
 Bytes: keyBytes,  
 }  
  
 keyFile, err := os.Create(filename) 
 defer keyFile.Close()  
 pem.Encode(keyFile, pemBlock)  
 if(err!=nil){

 }
 return nil  
}  
  
// 保存公钥到文件  
func savePublicKey(privateKey *rsa.PrivateKey, filename string) error {  
 publicKey := &privateKey.PublicKey  
 keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)    

 pemBlock := &pem.Block{  
 Type:  "PUBLIC KEY",  
 Bytes: keyBytes,  
 }  

 if(err!=nil){

 }
 keyFile, err := os.Create(filename)  
 defer keyFile.Close()  
  
 pem.Encode(keyFile, pemBlock)  
 return nil  
}