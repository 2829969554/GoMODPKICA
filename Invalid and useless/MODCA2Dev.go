package main  
  //http://127.0.0.1:8081/root.crt
  //MODCA2     2023/12/6 19:07
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
 "net"   
 //"net/url" 
 "encoding/asn1"
 "crypto/sha1" 

)  
  
func main() {  

 //MOD***************************
 MODx509:=x509.Certificate{}

 MODname := pkix.Name{}  
 //使用者信息参数
 MODname.SerialNumber = "2829969554,210654020"
 MODname.CommonName = "Alice ROOT"  
 MODname.EMAIL = []string{"2829969554@qq.com"}
 MODname.Organization=[]string{"China Program Ape Center"}
  MODname.OrganizationalUnit=   []string{"Go development"}
 MODname.Country=      []string{"CN"}
 MODname.Locality=        []string{"H.BeiJing"}
 MODname.Province=        []string{"Happy"}
 MODname.StreetAddress=   []string{"SKY STREET 101"}
 MODname.PostalCode=      []string{"110110"}
 MODname.EVTYPE=      []string{"Private Organization"}
 MODname.EVCITY=      []string{"BeiJing"}
 MODname.EVCT=      []string{"CN"}
 
 //MOD密钥位数
 MODKbit:=2048

 // 生成RSA密钥对  
 privateKey, err := rsa.GenerateKey(rand.Reader, MODKbit)  
 if err != nil {  
    fmt.Println("密钥对生成失败：", err)  
    return  
 }  

 // 提取公钥  
 publicKey := &privateKey.PublicKey  
  
 // 将公钥转换为[]byte  
 publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)  
 privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey) 
 fmt.Println(sha1.Sum(privateKeyDER))
 //MOD颁发者密钥
 var arr,arr2 [20]byte  
 arr=sha1.Sum(publicKeyDER)
 arr2=sha1.Sum(publicKeyDER)
 //颁发者密钥sha1
 priid:=arr[:]
 //使用者密钥sha1
 subid:=arr2[:]
 //证书序列号
 CERTID:=time.Now().Unix()

 // 签发日期
 modqianfaTime := "2001-07-19 15:30:00"  
 //过期时间
 modguoqiTime := "2033-07-19 15:30:00"  

//MOD授权者信息
MODissureocsp:=[]string{"http://ocsp"}
MODissurecrt:=[]string{"http://crt"}
MODissurecrl:=[]string{"http://crl","666"}
//使用者可选
MODuseyuming:=[]string{"qq.com"}
MODuseemail:=[]string{"2829969554@qq.com"}
MODuseip:=[]net.IP{net.ParseIP("192.168.1.101")}

 
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
    //签名算法
 MODx509.SignatureAlgorithm=15
 MODsuanfa:=MODx509.SignatureAlgorithm

 //密钥用途
    //CA一般为1|2|32|64,
    //用户证书SSL 为1|4|8|16
 MODx509.KeyUsage=1|2|32|64
 MODyongtu:=MODx509.KeyUsage
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
 MODx509.ExtKeyUsage=[]x509.ExtKeyUsage{1,2}
 MODjiaqiangyongfa:=MODx509.ExtKeyUsage
 //MOD证书策略 
 MODPolicyIdentifiers := []asn1.ObjectIdentifier{
    asn1.ObjectIdentifier{2,23,140,1,3},//EV扩展代码签名证书
    {2,23,140,1,1},         //EV扩展域名证书
    {1,3,6,1,5,5,7,2,1},  //为CPS限定标识符
    {1,3,6,1,5,5,7,2,2}, //为用户通告标识符

 }  


 //MOD添加其他增强型密钥用法 补充
 MODUnknownExtKeyUsage := []asn1.ObjectIdentifier{
   // asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,1},
     {1,3,6,1,4,1,311,10,3,5},  //windows硬件驱动验证
     {1,3,6,1,4,1,311,10,3,6},  //windows系统组件验证
     {1,3,6,1,4,1,311,10,3,7},  //OEMwindows系统组件验证
     {1,3,6,1,4,1,311,10,3,8},  //内嵌windows系统组件验证

 } 

 //******************************
 // 定义时间格式  不用动我
 modlayout := "2006-01-02 15:04:05"  
 // 使用time.Parse将字符串解析为time.Time类型  
 MODatime, err := time.Parse(modlayout, modqianfaTime)  
 if err != nil {  
 fmt.Println("解析时间错误:", err)  
 return  
 }  
 MODbtime, err := time.Parse(modlayout, modguoqiTime)  
 if err != nil {  
 fmt.Println("解析时间错误:", err)  
 return  
 }  
//*********************************

//MOD***********************
 // 创建证书模板  
 template := x509.Certificate{  
     SerialNumber: big.NewInt(CERTID),  
     Subject: MODname,/*pkix.Name{  
     CommonName:   "aaa", // 证书主题名称 
     EMAIL:[]string{"admin@qq.com"},//邮箱
     Organization: []string{"O"}, // 组织名称  
     Country:      []string{"CN"},
     SerialNumber:         "6666666666666", 
     OrganizationalUnit:   []string{"OU"},
     Locality:        []string{"L"},
     Province:        []string{"P"},
     StreetAddress:   []string{"ST"},
     PostalCode:      []string{"110110"},
     EVTYPE:      []string{"GUOJIA"},
     EVCITY:      []string{"BEIJING"},
     EVCT:      []string{"CN"},
 }, */ 
     NotBefore: MODatime, // 证书生效时间  
     NotAfter:  MODbtime, // 证书过期时间，这里设置为1年后的今天  
     

  //1    x509.KeyUsageDigitalSignature
  //2    x509.KeyUsageContentCommitment
  //4    x509.KeyUsageKeyEncipherment
  //8    x509.KeyUsageDataEncipherment
  //16   x509.KeyUsageKeyAgreement
  //32   x509.KeyUsageCertSign
  //64   x509.KeyUsageCRLSign
  //128  x509.KeyUsageEncipherOnly
  //256  x509.KeyUsageDecipherOnly
  //CA一般为1|2|32|64,
  //用户证书SSL 为1|4|8|16
  KeyUsage:MODyongtu, // 密钥用途，用于加密和数字签名  
     
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

     ExtKeyUsage:MODjiaqiangyongfa,/* []x509.ExtKeyUsage{    // 扩展密钥用途，用于服务器身份验证和客户端认证等  
     //代码签名 内核代码签名
     3,13,
 },*/

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
    SignatureAlgorithm:MODsuanfa, 

    BasicConstraintsValid: true,
    IsCA: true,
    // 非CA证书的基本约束有效，用于限制证书的使用范围 
    //MaxPathLen:3,
    //证书链最大层次


    //使用者密钥标识符和颁发者密钥标识符
    AuthorityKeyId:priid,
    SubjectKeyId:subid,

    //颁发者信息访问
    OCSPServer:MODissureocsp,
    IssuingCertificateURL:MODissurecrl,
    CRLDistributionPoints:MODissurecrt,
    //使用者可选名称
    DNSNames:MODuseyuming,
    EmailAddresses:MODuseemail,
    IPAddresses:MODuseip,
    /*
    URIs :[]*url.URL{  
     {Scheme: "http", Host: "aaa.com"},  
     {Scheme: "https", Host: "bbb.com"},  
     {Scheme: "ftp", Host: "ccc.org"},  
     }, 
     */
    PolicyIdentifiers:MODPolicyIdentifiers,
    //名称限制严格 名称约束
    /*
    PermittedDNSDomainsCritical:false,
    PermittedDNSDomains:[]string{"q1.com"},
    ExcludedDNSDomains:[]string{"q2.com"},
    */
}  





 // 使用证书模板和RSA密钥对生成证书  
 rootderBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)  
 if err != nil {  
 fmt.Println("ROOT证书生成失败：", err)  
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


}