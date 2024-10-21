package main  
  //配置文件位于MODPKICA系统根目录\PKI\CONFIG.txt
  //MODCA2     2024/10/20 19:07
import (  
 "crypto/rand"  
 "crypto/rsa"  
 "crypto/ecdsa"
 "crypto/elliptic"
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
 "crypto/sha256" 
 "path/filepath"
 "strings"
 "strconv"
 "bufio"
 "os/exec" 
 "modcrypto/gm/sm2"
 //"modcrypto/hash/sm3"
 sm2x509 "modcrypto/x509"
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
MODPKI_certdir:=MODTC+"\\PKI\\CERT\\"
MODPKI_keydir:=MODTC+"\\PKI\\KEY\\"
MODPKI_WebPublicCRTdir:=MODTC+"\\PKI\\WebPublic\\CRT\\"

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
 MODx509:=sm2x509.Certificate{}
 MODname := pkix.Name{}  
 //使用者信息参数

 // 使用逗号分隔字符串  
 substrings := strings.Split(MODML[1], ",")  

 Keyalgorithm:="RSA" 
 Keyalgorithm = MODML[4]  

 rootkeybit,err:=strconv.Atoi(MODML[2])
 if err != nil {
     //如果rootkeybit为空 默认密钥位数
     if(Keyalgorithm == "RSA"){
        rootkeybit=2048
     }
     if(Keyalgorithm == "ECC"){
        rootkeybit=256
     }
     if(Keyalgorithm == "SM2"){
        rootkeybit=256
     }
 }
     //防止输入的密钥位数超出范围 RSA:1024 - 8192  ECC 224 256 384 521  SM2 256
     if(Keyalgorithm == "RSA"){
        if(rootkeybit < 1024){
            rootkeybit=1024
        }
     }

     if(Keyalgorithm == "ECC"){
        if(rootkeybit <= 256){
            rootkeybit=256
        }

        if(rootkeybit > 256 && rootkeybit <= 384){
            rootkeybit=384
        }
        if(rootkeybit > 384){
            rootkeybit=521
        }
     }

     //SM2密钥长度只有256
     if(Keyalgorithm == "SM2"){
        rootkeybit=256
     }

 roothash :=MODx509.SignatureAlgorithm
//fmt.Println(MODML[3])
     switch MODML[3] {  
    case "sha1":  
        roothash=3
        if(Keyalgorithm=="ECC"){
           roothash=9 
        }
    case "sha256":  
        roothash=4 
        if(Keyalgorithm=="ECC"){
           roothash=10 
        }
    case "sha384":  
        roothash=5
        if(Keyalgorithm=="ECC"){
           roothash=11 
        }
    case "sha512":  
        roothash=6
        if(Keyalgorithm=="ECC"){
           roothash=12 
        }
    case "SHA256RSAPSS":  
        roothash=13 
    case "SHA384RSAPSS":  
        roothash=14 
    case "SHA512RSAPSS":  
        roothash=15 
    case "SM3":  
        roothash=333
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


 
 //MOD密钥位数
 MODKbit:=rootkeybit

var RSAprivateKey *rsa.PrivateKey
var ECCprivateKey *ecdsa.PrivateKey
var SM2privateKey *sm2.PrivateKey
fmt.Println("AAA",Keyalgorithm,MODKbit)  

if(Keyalgorithm =="RSA"){
     // 生成RSA密钥对  
     rsaprivateKey, err := rsa.GenerateKey(rand.Reader, MODKbit)  
     if err != nil {  
        fmt.Println("密钥对生成失败：", err)  
        return  
     }
     RSAprivateKey = rsaprivateKey
}

if(Keyalgorithm =="SM2"){
     // 生成SM2密钥对  
     sm2privateKey, err := sm2.GenerateKey(rand.Reader)  
     if err != nil {  
        fmt.Println("密钥对生成失败：", err)  
        return  
     }
     SM2privateKey = sm2privateKey
} 

if(Keyalgorithm =="ECC"){
    if(MODKbit == 224){
        eccprivateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
        if err != nil {  
           fmt.Println("密钥对生成失败：", err)  
           return  
        }
        ECCprivateKey = eccprivateKey        
    }
    if(MODKbit == 256){
        eccprivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        if err != nil {  
           fmt.Println("密钥对生成失败：", err)  
           return  
        }
        ECCprivateKey = eccprivateKey        
    }
    if(MODKbit == 384){
        eccprivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
        if err != nil {  
           fmt.Println("密钥对生成失败：", err)  
           return  
        }
        ECCprivateKey = eccprivateKey

        fmt.Println("256",ECCprivateKey,eccprivateKey)        
    }
    if(MODKbit == 521){
        eccprivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
        if err != nil {  
           fmt.Println("密钥对生成失败：", err)  
           return  
        } 
        ECCprivateKey = eccprivateKey     
    }
}

fmt.Println(RSAprivateKey,ECCprivateKey)

var publicKeyDER []byte

if(Keyalgorithm =="RSA"){
 // 提取公钥  
 publicKey := &RSAprivateKey.PublicKey   
 // 将公钥转换为[]byte  
 publicKeyDERbyte, _ := x509.MarshalPKIXPublicKey(publicKey) 
 publicKeyDER = publicKeyDERbyte
}

if(Keyalgorithm =="SM2"){
 // 提取公钥  
 publicKey := &SM2privateKey.PublicKey
 // 将公钥转换为[]byte
 publicKeyDERbyte, _ := sm2.MarshalPublicKey(publicKey) 
 publicKeyDER = publicKeyDERbyte
}

if(Keyalgorithm =="ECC"){
 // 提取公钥  
 publicKey := &ECCprivateKey

 // 将公钥转换为[]byte  
 publicKeyDERbyte, _ := x509.MarshalPKIXPublicKey(publicKey) 
 publicKeyDER = publicKeyDERbyte
}
 

 //privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey) 
 //fmt.Println(sha1.Sum(privateKeyDER))
 //MOD颁发者密钥
 var arr,arr2 []byte  
     hash := sha256.New()
    hash.Write(publicKeyDER)
 arr=hash.Sum(nil)
 arr2=hash.Sum(nil)
 //颁发者密钥sha1
 priid:=arr[:]
 //使用者密钥sha1
 subid:=arr2[:]
 //证书序列号  //根证书序列号数值大于90000000000000000
 CERTID:=big.NewInt(90000000000000000 + time.Now().UTC().Unix())
 //使用者证书类型 true为CA，false为最终实体
 CertIsCA:=true
 // 签发日期
 modqianfaTime := "2001-07-19 15:30:00"  
 //过期时间
 modguoqiTime := "2099-07-19 15:30:00"  

//MOD授权者信息
MODSUCRT=strings.Replace(MODSUCRT, "{CID}", CERTID.Text(16), -1)
MODSUCRL=strings.Replace(MODSUCRL, "{CID}", CERTID.Text(16), -1)
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
 MODsuanfa:=MODx509.SignatureAlgorithm

 if(Keyalgorithm != "SM2"){
    MODx509.SignatureAlgorithm=roothash
    MODsuanfa=MODx509.SignatureAlgorithm
 }


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
 MODx509.ExtKeyUsage=[]sm2x509.ExtKeyUsage{}
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
 template := sm2x509.Certificate{  
     SerialNumber:CERTID,  
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
     NotBefore: MODatime.UTC(), // 证书生效时间  
     NotAfter:  MODbtime.UTC(), // 证书过期时间，这里设置为1年后的今天  
     

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
        Critical: true, //预证书这个必须为true
        Value:    []byte{0x05,0x00},
    }
*/


    //定义SCT结构体
    var mysct SCT
    //版本号
    mysct.Version = 0
    //证书透明度日志ID
    mysct.LogID = subid
    //签署实时数据戳UTC时间，精确到毫秒
    mysct.Timestamp = uint64(time.Now().UTC().UnixMilli())
    //等待签名数据的哈希算法 0:none  1:MD5  2:SHA1  3:SHA224  4:SHA256   5:SHA384  6:SHA512
    mysct.Hash = 4
    //签名算法 0:anonymous  1:RSA  2:DSA  3:ECDSA
    mysct.Signtype = 3
    //签名内容
    mysct.Signature = SCTGenerateSignature()
    //fmt.Println("长度",len(mysct.Signature))
    //根据上述参数创建SCT结构数据
    mysct.CreateSCT()

    //定义并创建SCT列表结构体数据
    var mysctlist SCTList
    mysctlist = SCTList{
        //将2组SCT结构套在一起
        SCTs: []SCT{mysct},
    }

    //生成SCT列表 ASN.1数据  status是状态True|False   sctans1data为 SCT列表的ASN.1数据
    _,sctans1data:= mysctlist.CreateSCTList()

    // 创建一个CT扩展 证书透明度
    ctExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
        Critical: false,
        Value:    sctans1data,
    }
    

    /*MOD新版CPS模块待更新*/
    // 创建一个CPS扩展
    cpsURL := "https://baidu.com"
    cpsTEXT:= `我是可信根证书`

    cpsExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{2,5,29,32},
        Critical: false,
        Value:    GenerateCPSbyte([]asn1.ObjectIdentifier{{2,23,140,1,4,1},{2,23,140,1,4,2}},cpsURL,cpsTEXT),
    }

         
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
        ctExtension,
        //noocspExtension,
        //ocspmustExtension,
        cpsExtension,
        }

 // 使用证书模板和RSA密钥对生成证书  

 var rootderBytes []byte
 if(Keyalgorithm =="RSA"){
     rootderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, &template, &RSAprivateKey.PublicKey, RSAprivateKey)  
     if err != nil {  
     fmt.Println("RSA ROOT证书生成失败：", err)  
     return  
     } 
    rootderBytes = rootderBytestmp
 }

 if(Keyalgorithm =="ECC"){
     rootderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, &template, &ECCprivateKey.PublicKey, ECCprivateKey)  
     if err != nil {  
     fmt.Println("ECC ROOT证书生成失败：", err)  
     return  
     } 
    rootderBytes = rootderBytestmp
 }

 if(Keyalgorithm =="SM2"){
     rootderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, &template, &SM2privateKey.PublicKey, SM2privateKey)  
     if err != nil {  
     fmt.Println("SM2 ROOT证书生成失败：", err)  
     return  
     } 
    rootderBytes = rootderBytestmp
 } 

 // 将证书文件保存到ROOT目录 
 certOut, err := os.Create(MODPKI_rootdir+"root.crt")  
 if err != nil {  
 fmt.Println("ROOT无法创建证书文件：", err)  
 return  
 }  
 pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: rootderBytes})  
 certOut.Close()  

 // 将证书文件保存到WebPublic\CRT公开副本目录
 certOut2, err := os.Create(MODPKI_WebPublicCRTdir + template.SerialNumber.Text(16)+ ".crt")  
 if err != nil {  
 fmt.Println("ROOT无法创建证书文件：", err)  
 return  
 }  
 pem.Encode(certOut2, &pem.Block{Type: "CERTIFICATE", Bytes: rootderBytes})  
 certOut2.Close()  

 // 将证书文件保存到CERT目录
 certOut3, err := os.Create(MODPKI_certdir + template.SerialNumber.Text(16)+ ".crt")  
 if err != nil {  
 fmt.Println("ROOT无法创建证书文件：", err)  
 return  
 }  
 pem.Encode(certOut3, &pem.Block{Type: "CERTIFICATE", Bytes: rootderBytes})  
 certOut3.Close()  

 // 将证书文件保存到root目录
 certOut33, err := os.Create(MODPKI_rootdir + template.SerialNumber.Text(16)+ ".crt")  
 if err != nil {  
 fmt.Println("ROOT无法创建证书文件：", err)  
 return  
 }  
 pem.Encode(certOut33, &pem.Block{Type: "CERTIFICATE", Bytes: rootderBytes})  
 certOut33.Close()  

if(Keyalgorithm =="RSA"){
    saveRSAPrivateKey(RSAprivateKey,MODPKI_rootdir + "root.key")
    saveRSAPrivateKey(RSAprivateKey,MODPKI_rootdir + template.SerialNumber.Text(16) + ".key")
    saveRSAPrivateKey(RSAprivateKey,MODPKI_keydir + template.SerialNumber.Text(16) + ".key")
}
if(Keyalgorithm =="ECC"){
    saveECCPrivateKey(ECCprivateKey,MODPKI_rootdir + "root.key")
    saveECCPrivateKey(ECCprivateKey,MODPKI_rootdir + template.SerialNumber.Text(16) + ".key")
    saveECCPrivateKey(ECCprivateKey,MODPKI_keydir + template.SerialNumber.Text(16) + ".key")
}
if(Keyalgorithm =="SM2"){
    saveSM2PrivateKey(SM2privateKey,MODPKI_rootdir + "root.key")
    saveSM2PrivateKey(SM2privateKey,MODPKI_rootdir + template.SerialNumber.Text(16) + ".key")
    saveSM2PrivateKey(SM2privateKey,MODPKI_keydir + template.SerialNumber.Text(16) + ".key")
}

ags:=[]string {"newcert",template.SerialNumber.Text(16),"R", "V","0","null",template.SerialNumber.Text(16),Keyalgorithm,}
    cmd2:=exec.Command(MODAUTOEXE, "init")  
    cmd2.CombinedOutput() 
    cmd3:=exec.Command(MODAUTOEXE, ags...)  
    cmd3.CombinedOutput() 
    cmd4:=exec.Command(MODrootGETcrl,)  
    cmd4.CombinedOutput() 


}

// 保存私钥到文件  
func saveRSAPrivateKey(privateKey *rsa.PrivateKey, filename string) error {  
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

func saveECCPrivateKey(privateKey *ecdsa.PrivateKey, filename string) error {  
 keyBytes,_ := x509.MarshalECPrivateKey(privateKey)  
 pemBlock := &pem.Block{  
 Type:  "EC PRIVATE KEY",  
 Bytes: keyBytes,  
 }  
  
 keyFile, err := os.Create(filename) 
 defer keyFile.Close()  
 pem.Encode(keyFile, pemBlock)  
 if(err!=nil){

 }
 return nil  
} 

func saveSM2PrivateKey(privateKey *sm2.PrivateKey, filename string) error {  
 keyBytes,_ := sm2.MarshalPrivateKey(privateKey)
 pemBlock := &pem.Block{  
 Type:  "SM2 PRIVATE KEY",  
 Bytes: keyBytes,  
 }  
  
 keyFile, err := os.Create(filename) 
 defer keyFile.Close()  
 pem.Encode(keyFile, pemBlock)  
 if(err!=nil){

 }
 return nil  
} 