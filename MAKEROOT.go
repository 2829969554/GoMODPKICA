package main  
  //配置文件位于PKI\CONFIG.txt
  //MODCA2     2023/12/9 15:07
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
 "path/filepath"
 "strings"
 "strconv"
 "bufio"
 "os/exec"  
)  
//去掉结尾的\r\n
func rftrn(s string) string {  
 for len(s) > 0 && s[len(s)-1] == '\n' {  
 s = s[:len(s)-1]  
 }  
 s=rftrr(s) 
 return  s
}
//去掉\r
func rftrr(s string) string {  
 for len(s) > 0 && s[len(s)-1] == '\r' {  
 s = s[:len(s)-1]  
 }  
 return s  
}

func main() {
MODML:=os.Args
MODSUCRL:=""
MODSUCRT:=""
MODSUOCSP:=""
 ex, err := os.Executable()  
 if err != nil {  
 panic(err)  
 } 
 //当前执行目录
MODTC:= filepath.Dir(ex)  
//配置授权信息配置
MODCONFIG:=MODTC+"\\PKI\\CONFIG.txt"
MODAUTOEXE:=MODTC+"\\PKI\\auto.exe"
MODrootGETcrl:=MODTC+"\\rootGETcrl.exe"
//特定目录
MODPKI_rootdir:=MODTC+"\\PKI\\ROOT\\" 
    // 打开文件  
    file, err := os.Open(MODCONFIG)  
    if err != nil {  
        fmt.Println(err)  
        return  
    }  
    defer file.Close()  
    // 创建一个新的 Reader  
    reader := bufio.NewReader(file)  
    // 循环读取每一行  
    for{  
        line, err := reader.ReadString('\n')  
        if err != nil {  
            break 
        } 
        if(line[0]=='#'){
            continue
        }
        parts := strings.Split(line, "=")
        if(parts[0]=="CRL"){
            MODSUCRL=rftrn(parts[1])
        }
        if(parts[0]=="CRT"){
            MODSUCRT=rftrn(parts[1])
        }
        if(parts[0]=="OCSP"){
            MODSUOCSP=rftrn(parts[1])
        }
    } 



 //MOD***************************
 MODx509:=x509.Certificate{}
 MODname := pkix.Name{}  
 //使用者信息参数

 // 使用逗号分隔字符串  
 substrings := strings.Split(MODML[1], ",")  
 rootkeybit,err:=strconv.Atoi(MODML[2])
 if err != nil {
     rootkeybit=2048
 }
    if(rootkeybit<=1024){
        rootkeybit=1024
    }
 roothash :=MODx509.SignatureAlgorithm
//fmt.Println(MODML[3])
     switch MODML[3] {  
    case "sha1":  
        roothash=3
    case "sha256":  
        roothash=4 
    case "sha384":  
        roothash=5
    case "sha512":  
        roothash=6 
    case "SHA256RSAPSS":  
        roothash=13 
    case "SHA384RSAPSS":  
        roothash=14 
    case "SHA512RSAPSS":  
        roothash=15 
    default:  
        roothash=3
    }  
 for _, substring := range substrings {  
     // 使用等号分隔子字符串  
     parts := strings.Split(substring, "=")  
   
     if len(parts) == 2 {  
         key := parts[0]  
         value := parts[1]

        //********************
        //把%改为空格
        value=strings.Replace(value, "%", " ", -1)
        if(value==""){
            continue
        }
        if(key=="SERIALNUMBER"){
            MODname.SerialNumber = value
        }
        if(key=="CN"){
             MODname.CommonName = value
        }
        if(key=="O"){
            MODname.Organization=[]string{value}
        }
        if(key=="OU"){
            MODname.OrganizationalUnit= []string{value} 
        }
        if(key=="C"){
            MODname.Country=      []string{value} 
        }
        if(key=="L"){
            MODname.Locality=     []string{value}
        }
        if(key=="S"){
            MODname.Province=        []string{value} 
        }
        if(key=="STREET"){
            MODname.StreetAddress=   []string{value} 
        }
        if(key=="PostalCode"){
            MODname.PostalCode=      []string{value}
        }


        //****************** 
         } else {  
         fmt.Println("Invalid substring:", substring)  
     }  
 }




 

 //MODname.EMAIL = []string{"2829969554@qq.com"}
 
  
 
 
 
 
 
 //MODname.EVTYPE=      []string{"Private Organization"}
 //MODname.EVCITY=      []string{"BeiJing"}
 //MODname.EVCT=      []string{"CN"}
 
 //MOD密钥位数
 MODKbit:=rootkeybit

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
 //使用者证书类型 true为CA，false为最终实体
 CertIsCA:=true
 // 签发日期
 modqianfaTime := "2001-07-19 15:30:00"  
 //过期时间
 modguoqiTime := "2099-07-19 15:30:00"  

//MOD授权者信息
MODissureocsp:=[]string{MODSUOCSP}
MODissurecrt:=[]string{MODSUCRT}
MODissurecrl:=[]string{MODSUCRL}
//使用者可选
MODuseyuming:=[]string{
    //"qq.com"
}
MODuseemail:=[]string{
    //"2829969554@qq.com"
}
MODuseip:=[]net.IP{
   // net.ParseIP("192.168.1.101")
}

 
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
 MODx509.SignatureAlgorithm=roothash
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
 MODx509.ExtKeyUsage=[]x509.ExtKeyUsage{}
 MODjiaqiangyongfa:=MODx509.ExtKeyUsage
 //MOD证书策略 
 MODPolicyIdentifiers := []asn1.ObjectIdentifier{
    {2,23,140,1,3},//EV扩展代码签名证书
    {2,23,140,1,1},         //EV扩展域名证书
    //{1,3,6,1,5,5,7,2,1},  //为CPS限定标识符
    //{1,3,6,1,5,5,7,2,2}, //为用户通告标识符

 }  


 //MOD添加其他增强型密钥用法 补充
 MODUnknownExtKeyUsage := []asn1.ObjectIdentifier{
   // asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,1},
  /*   {1,3,6,1,4,1,311,10,3,5},  //windows硬件驱动验证
     {1,3,6,1,4,1,311,10,3,6},  //windows系统组件验证
     {1,3,6,1,4,1,311,10,3,7},  //OEMwindows系统组件验证
     {1,3,6,1,4,1,311,10,3,8},  //内嵌windows系统组件验证
*/
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
    IsCA: CertIsCA,
    // 非CA证书的基本约束有效，用于限制证书的使用范围 
    //MaxPathLen:3,
    //证书链最大层次


    //使用者密钥标识符和颁发者密钥标识符
    AuthorityKeyId:priid,
    SubjectKeyId:subid,

    //颁发者信息访问
    OCSPServer:MODissureocsp,
    IssuingCertificateURL:MODissurecrt,
    CRLDistributionPoints:MODissurecrl,
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
    /*
    // 创建一个CT预证书扩展
    ctyExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
        Critical: false, //预证书这个必须为true
        Value:    []byte{0x05,0x00},
    }

    // 创建一个CT扩展 证书透明度
    ctExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
        Critical: false,
        Value:    []byte{0x04,0x82,0x01,0x6B,0x01,0x69,0x00,0x77,0x00,0xEE,0xCD,0xD0,0x64,0xD5,0xDB,0x1A,0xCE,0xC5,0x5C,0xB7,0x9D,0xB4,0xCD,0x13,0xA2,0x32,0x87,0x46,0x7C,0xBC,0xEC,0xDE,0xC3,0x51,0x48,0x59,0x46,0x71,0x1F,0xB5,0x9B,0x00,0x00,0x01,0x8B,0x88,0xD1,0x0B,0x5A,0x00,0x00,0x04,0x03,0x00,0x48,0x30,0x46,0x02,0x21,0x00,0xC5,0x80,0xD8,0xA0,0xDC,0xBC,0xD5,0x56,0x81,0x4F,0x94,0x35,0x02,0x38,0xE5,0x83,0x9C,0x60,0xE8,0xE6,0x38,0xE6,0x29,0x59,0xC7,0x81,0xF1,0xCD,0x26,0xF8,0x12,0xA0,0x02,0x21,0x00,0xBD,0x27,0x2A,0x90,0xC1,0xB4,0xA4,0x8D,0x67,0x7F,0xE7,0xE9,0xED,0xF6,0x5A,0xA4,0x72,0x47,0x93,0x3A,0xCB,0x91,0x87,0x91,0x4F,0xB8,0xCE,0xCB,0xC2,0xE8,0x7D,0x92,0x00,0x76,0x00,0x48,0xB0,0xE3,0x6B,0xDA,0xA6,0x47,0x34,0x0F,0xE5,0x6A,0x02,0xFA,0x9D,0x30,0xEB,0x1C,0x52,0x01,0xCB,0x56,0xDD,0x2C,0x81,0xD9,0xBB,0xBF,0xAB,0x39,0xD8,0x84,0x73,0x00,0x00,0x01,0x8B,0x88,0xD1,0x0B,0x22,0x00,0x00,0x04,0x03,0x00,0x47,0x30,0x45,0x02,0x20,0x0C,0xC1,0x6F,0x53,0x1B,0x74,0xFD,0x0D,0x96,0x20,0x87,0x36,0xC9,0xE3,0xAA,0xEF,0xD7,0xAF,0x8F,0xFC,0x17,0xB1,0x3C,0x6A,0xAB,0x79,0x3E,0x6D,0x1B,0x72,0x1A,0xC0,0x02,0x21,0x00,0x8F,0x87,0x4E,0x7F,0xEC,0x7F,0x71,0x14,0x9B,0xC2,0x97,0x5A,0xAE,0xA2,0xC6,0x1E,0xD9,0x97,0x1B,0x3F,0xD3,0x99,0xAB,0x21,0x0D,0x1E,0x1E,0xC6,0x10,0x2D,0x4A,0x03,0x00,0x76,0x00,0xDA,0xB6,0xBF,0x6B,0x3F,0xB5,0xB6,0x22,0x9F,0x9B,0xC2,0xBB,0x5C,0x6B,0xE8,0x70,0x91,0x71,0x6C,0xBB,0x51,0x84,0x85,0x34,0xBD,0xA4,0x3D,0x30,0x48,0xD7,0xFB,0xAB,0x00,0x00,0x01,0x8B,0x88,0xD1,0x0B,0x1E,0x00,0x00,0x04,0x03,0x00,0x47,0x30,0x45,0x02,0x20,0x43,0xE0,0xC3,0x5A,0xD1,0x59,0xFD,0x09,0x80,0x14,0x4E,0xE0,0x0C,0x38,0xE4,0x19,0x06,0x90,0x59,0xD5,0x91,0x1C,0x72,0x3B,0xA6,0x1F,0x74,0x09,0x85,0xCC,0x30,0x19,0x02,0x21,0x00,0xC2,0x02,0xC0,0x7D,0x0D,0x55,0xE4,0xED,0x73,0x51,0x98,0x87,0x40,0xD5,0x81,0x23,0x4A,0xD9,0x43,0x4D,0x19,0x14,0x80,0x19,0xB7,0x47,0x12,0xA2,0xAB,0xB1,0x75,0xE3},
        }
    */
    /*MOD新版CPS模块待更新
    // 创建一个CPS扩展
    cpsExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{2,5,29,32},
        Critical: false,
        //CPS链接
        //Value:    []byte{0x30,0x41,0x30,0x0B,0x06,0x09,0x60,0x86,0x48,0x01,0x86,0xFD,0x6C,0x02,0x01,0x30,0x32,0x06,0x05,0x67,0x81,0x0C,0x01,0x01,0x30,0x29,0x30,0x27,0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x01,0x16,0x1B,0x68,0x74,0x74,0x70,0x3A,0x2F,0x2F,0x77,0x77,0x77,0x2E,0x64,0x69,0x67,0x69,0x63,0x65,0x72,0x74,0x2E,0x63,0x6F,0x6D,0x2F,0x43,0x50,0x53},
        
        //用户通告
        Value:[]byte{0x30,0x4F,0x30,0x4D,0x06,0x09,0x60,0x86,0x48,0x01,0x86,0xFD,0x6C,0x02,0x01,0x30,0x40,0x30,0x28,0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x01,0x16,0x1C,0x68,0x74,0x74,0x70,0x73,0x3A,0x2F,0x2F,0x77,0x77,0x77,0x2E,0x64,0x69,0x67,0x69,0x63,0x65,0x72,0x74,0x2E,0x63,0x6F,0x6D,0x2F,0x43,0x50,0x53,0x30,0x14,0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x02,0x02,0x30,0x08,0x1A,0x06,0x31,0x32,0x33,0x34,0x35,0x36},


         }

     */    
    // 创建一个OCSP不撤销检查扩展
    /*
    noocspExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1,3,6,1,5,5,7,48,1,5},
        Critical: false,
        Value:    []byte{0x05,0x00},
    }
    // 创建一个OCSP MUST装订扩展
    ocspmustExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1,3,6,1,5,5,7,1,24},
        Critical: false,
        Value:    []byte{0x30,0x03,0x02,0x01,0x05},
    }
    */
    // 创建一个CA版本号扩展 最后一位版本号3.0
    caverExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1,3,6,1,4,1,311,21,1},
        Critical: false,
        Value:    []byte{0x02,0x01,0x03},
    }
    //MOD加入x509扩展
    template.ExtraExtensions = []pkix.Extension{
        caverExtension,
        //ctyExtension,
        //ctExtension,
        //noocspExtension,
        //ocspmustExtension,
        //cpsExtension,
        }

 // 使用证书模板和RSA密钥对生成证书  
 rootderBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)  
 if err != nil {  
 fmt.Println("ROOT证书生成失败：", err)  
 return  
 }  

 // 将证书保存到文件  
 certOut, err := os.Create(MODPKI_rootdir+"root.crt")  
 if err != nil {  
 fmt.Println("ROOT无法创建证书文件：", err)  
 return  
 }  
 pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: rootderBytes})  
 certOut.Close()  
 fmt.Println("ROOT证书生成成功！")  

 // 将证书保存到文件  
 certOut2, err := os.Create(MODTC+"\\PKI\\WebPublic\\CRT\\root.crt")  
 if err != nil {  
 fmt.Println("ROOT无法创建证书文件：", err)  
 return  
 }  
 pem.Encode(certOut2, &pem.Block{Type: "CERTIFICATE", Bytes: rootderBytes})  
 certOut2.Close()  
 fmt.Println("ROOT证书生成成功！")  

 savePrivateKey(privateKey,MODPKI_rootdir+"root.key")
ags:=[]string {"newcert",template.SerialNumber.Text(16),"R", "V","0",}
    cmd2:=exec.Command(MODAUTOEXE, "init")  
    cmd2.CombinedOutput() 
    cmd3:=exec.Command(MODAUTOEXE, ags...)  
    cmd3.CombinedOutput() 
    cmd4:=exec.Command(MODrootGETcrl,)  
    cmd4.CombinedOutput() 


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