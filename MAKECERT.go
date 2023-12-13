package main  
  //配置文件位于PKI\CONFIG.txt
  //MODCA2     2023/12/6 19:07
  /* 签发用户证书 subname 参数1(格式:key:value 分隔符:,)   
    可填null空   keybit  参数2(格式:4096 例子:1024|2048|4096|8192) 
    可填null空   hash    参数3(格式:sha1 例子:sha1|sha256|sha384|sha512|...)
    可填null空   usage   参数4(格式:1 例子:1.用户证书 2.中间CA 3.仅用于加密证书 4.仅用于解密证书)
                              中间CA一般为1,2,32,64 | 用户证书为1,4,8,16 |3.只能加密128|4.只能解密256
     可填null空  exusage 参数5(格式:1,2,3 分隔符:, 例子:0,1,2,3,4,5,6,7,8,9,10,11,12,13)
     可填null空  type    参数6(格式:0 例子:0或1;0:用户证书 1:为中间CA;可空默认为0)
     可填null空  time    参数7(格式1:1 例子:以当前日期为起点计算1年,可以填30,代表30年。默认为1)
                              (格式2:2015/12/08-21:18:57T2025/12/08-21:18:57 分隔符:T 例子:时间按照这种格式指定有效)
     可填null空  URLS    参数8(格式:abc.com 分隔符:, 例子:abc.com,aaa.com,bbb.com多域名SSL可选)
     可填null空  IP      参数9(格式:192.168.101.100 分隔符:,例子:192.168.101.100,192.168.102.102,192.168.103.103多IP SSL可选)
     可填null空  Kernel  参数10(格式:1或者null 如果是1则加入windwos内核签名用法)
例如全null 命令:makecert CN=test null null null null null null null null null
                全null 意思是生成一个CN为test的sha1的1024位的全功能用户证书（无增强密钥用法）无特定用法，有效期1年支持吊销
例如SSL域名 makecert CN=test.com 2048 sha256 0 1,2 0 1 test.com null
            这行意思是生成一个2048位sha256的用户DV 域名 SSL证书 全功能，增强用法是服务器验证客户端验证 有效期1年
           makecert CN=127.0.0.1 2048 sha256 0 1,2 0 1 null 127.0.0.1 null
           这行意思是生成一个2048位sha256的用户DV IP SSL证书 全功能，增强用法是服务器验证客户端验证 有效期1年
例如代码签名 EV代码签名 makecert CN=我是EV证书,O=中国公司,OU=研发部,EVCT=CN,EVCITY=BEIJING,EVTYPE=PrivateBank 2048 sha256 0 3 0 1 null null 1
            带有EV扩展标识支持驱动
            。。。。扩展性很强。。这里就不举例子了
             */
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
 "io/ioutil"
 "log"  
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
//MODrootGETcrl:=MODTC+"\\rootGETcrl.exe"
//特定目录
MODPKI_rootdir:=MODTC+"\\PKI\\ROOT\\" 
MODPKI_certdir:=MODTC+"\\PKI\\CERT\\" 
MODPKI_keydir:=MODTC+"\\PKI\\KEY\\" 

MODTIMSTAMPdir:=MODTC+"\\PKI\\TIMSTAMP\\"   //时间戳服务根目录
TSACERTsha1crt:=MODTIMSTAMPdir+"sha1.crt" 
TSACERTsha1key:=MODTIMSTAMPdir+"sha1.key"
TSACERTsha256crt:=MODTIMSTAMPdir+"sha256.crt"
TSACERTsha256key:=MODTIMSTAMPdir+"sha256.key"

    // 打开配置文件  
    file, err := os.Open(MODCONFIG)  
    if err != nil {  
        fmt.Println(err)  
        return  
    }  
    defer file.Close()  
    // 创建一个新的 Reader  
    reader := bufio.NewReader(file)  
    // 循环读取每一行  加载配置
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


//MOD 解码颁发者证书和颁发者私钥

 // 读取证书文件  
 rootPEM, err := ioutil.ReadFile(MODPKI_rootdir+"root.crt")  
 if err != nil {  
 log.Fatalf("无法读取证书文件：%v", err)  
 }  
 //fmt.Println(string(certPEM))
 // 读取私钥文件  
 rootkeyPEM, err := ioutil.ReadFile(MODPKI_rootdir+"root.key")  
 if err != nil {  
 log.Fatalf("无法读取私钥文件：%v", err)  
 }  
  
 // 解码证书  
 crtblock, _ := pem.Decode(rootPEM)  
  if crtblock == nil || crtblock.Type != "CERTIFICATE"{  
 log.Fatal("无效的PEM证书")  
 }  
 // 解码密钥  
 keyblock, _ := pem.Decode(rootkeyPEM) 
if keyblock == nil || keyblock.Type != "RSA PRIVATE KEY" {  
 log.Fatal("无效的KEY证书")  
 }  

 // 加载证书和私钥  
 rootcert, err := x509.ParseCertificate(crtblock.Bytes)  
 if err != nil {  
 log.Fatalf("无法解析证书：%v", err)  
 }  
 rootkey, err := x509.ParsePKCS1PrivateKey(keyblock.Bytes)  
 if err != nil {  
 fmt.Println("无法解析私钥：%v", err)  
 }  



 //MOD***************************
 MODx509:=x509.Certificate{}
 MODname := pkix.Name{}  
 //使用者信息参数




  // 使用逗号分隔字符串  
 substrings := strings.Split(MODML[1], ",") 

  
var certkeybit int
if(MODML[1]=="initOCSP" || MODML[1]=="initTIMSTAMP"){
   certkeybit=2048
}else{
    certkeybit,err=strconv.Atoi(MODML[2]) 
} 

 if err != nil {
     certkeybit=2048
 }
    if(certkeybit<=1024){
        certkeybit=1024
    }
 roothash :=MODx509.SignatureAlgorithm
if(MODML[1] != "initOCSP" && MODML[1] != "initTIMSTAMP"){
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
}



  //解析传递过来的命令[1]    
 for _, substring := range substrings { 

        if(MODML[1] == "initOCSP" || MODML[1] == "initTIMSTAMP"){
            break
        } 
     // 使用等号分隔子字符串  
     parts := strings.Split(substring, "=")  
   
     if len(parts) == 2 {  
         key := parts[0]  
         value := parts[1] 
         //fmt.Println(key,value)
        //********************
        //把%改为空格
        value=strings.Replace(value, "%", " ", -1)
        //判断又没有空参数，有就跳过
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
        if(key=="EVTYPE"){
            MODname.EVTYPE=      []string{value}
        }
        if(key=="EVCITY"){
            MODname.EVCITY=      []string{value}
        }
        if(key=="EMAIL"){
            MODname.EMAIL=      []string{value}
        }
        if(key=="EVCT"){
            MODname.EVCT=      []string{value}
        }

        //****************** 
         } else {  
         fmt.Println("Invalid substring:", substring)  
     }  
 }


 
 //MOD密钥位数
 MODKbit:=certkeybit

if(MODML[1]=="initOCSP" || MODML[1] == "initTIMSTAMP"){

    MODKbit=2048 
    roothash=3
    MODname = pkix.Name{} 
    MODname.CommonName = rootcert.Subject.CommonName+" By OCSP"
    MODname.Organization=rootcert.Subject.Organization
    MODname.OrganizationalUnit= []string{"Only OCSP Signing"} 
    if(MODML[1] == "initTIMSTAMP" && MODML[2] == "SHA1"){
        roothash=3
        MODname.OrganizationalUnit= []string{"Only TSA SHA1 Signing"} 
        MODname.CommonName = rootcert.Subject.CommonName+" By Timstamp SHA1"
    }
    if(MODML[1] == "initTIMSTAMP" && MODML[2] == "SHA256"){
        roothash=4
        MODname.OrganizationalUnit= []string{"Only TSA SHA256 Signing"} 
        MODname.CommonName = rootcert.Subject.CommonName+" By Timstamp SHA256"
    }
}

 // 生成RSA密钥对  
 certprivateKey, err := rsa.GenerateKey(rand.Reader, MODKbit)  
 if err != nil {  
    fmt.Println("密钥对生成失败：", err)  
    return  
 }  

 // 提取root公钥  
 rootpublicKey := &rootkey.PublicKey  
 // 提取cert公钥  
 certpublicKey := &certprivateKey.PublicKey 

 // 将公钥转换为[]byte  
 rootpublicKeyDER, err := x509.MarshalPKIXPublicKey(rootpublicKey)  
 certpublicKeyDER, err := x509.MarshalPKIXPublicKey(certpublicKey)  
 
 //MOD颁发者密钥
 var arr,arr2 [20]byte  
 arr=sha1.Sum(rootpublicKeyDER)
 arr2=sha1.Sum(certpublicKeyDER)
 //颁发者密钥sha1
 priid:=arr[:]
 //使用者密钥sha1
 subid:=arr2[:]
 //证书序列号
 CERTID:=time.Now().Unix()
 //使用者证书类型 true为CA，false为最终实体

 CertIsCA:=false
 // 签发日期
 modqianfaTime := "2011/12/08-21:18:57"
 //过期时间
 modguoqiTime := "2051/01/02-15:04:05"  
 if(len(MODML)>=7){
   if(MODML[6]=="1"){
        CertIsCA=true//设置为中间CA,默认为0
   }  
   if(len(MODML)==8){
    txtime:=MODML[7]
        if(len(txtime)<5){
            qishin:=1
            if(txtime!="null"){
                qishin,err=strconv.Atoi(txtime)
                if err != nil {
                    qishin=1
                }
            }
            modqianfaTime = time.Now().Format("2006/01/02-15:04:05")
            modguoqiTime=time.Now().Add(time.Hour * 24 * 365 * time.Duration(qishin)).Format("2006/01/02-15:04:05")
        }else{
            result := strings.Split(txtime,"T")  
            if(len(result)==2){
               modqianfaTime=result[0] 
               modguoqiTime=result[1] 
            }
        }

   }
 }
//MOD授权者信息
MODissureocsp:=[]string{MODSUOCSP}
MODissurecrt:=[]string{MODSUCRT}
MODissurecrl:=[]string{MODSUCRL}
//使用者可选
MODuseyuming:=[]string{
    //"qq.com"
}
//加入使用者可选遍历多个域名
if(len(MODML)>=9){
    ymlist:=MODML[8]
    if(ymlist!="null"){
         if strings.Contains(ymlist, ",") {  
            //存在分隔符 *****************
            ymlistrow:=strings.Split(ymlist,",") 
            for _, substring := range ymlistrow {
                MODuseyuming=append(MODuseyuming,substring) 
            }

            //************************
         } else {  
            //不存在分割符
            MODuseyuming=append(MODuseyuming,ymlist)  
         }  
    }
}
//当前邮箱加入使用者可选标识符
MODuseemail:=[]string{
}
if(MODname.EMAIL != nil){
    MODuseemail=append(MODuseemail,MODname.EMAIL[0])
}
MODuseip:=[]net.IP{
   // net.ParseIP("192.168.1.101")
}
//加入使用者可选遍历ip
if(len(MODML)>=10){
    iplist:=MODML[9]
    if(iplist!="null"){
         if strings.Contains(iplist, ",") {  
            //存在分隔符 *****************
            iplistrow:=strings.Split(iplist,",") 
            for _, substring := range iplistrow {
                MODuseip=append(MODuseip,net.ParseIP(substring)) 
            }

            //************************
         } else {  
            //不存在分割符
            MODuseip=append(MODuseip,net.ParseIP(iplist))  
         }  
    }
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
 MODx509.KeyUsage=1|2|4|8|16
 if(CertIsCA==true){
    MODx509.KeyUsage=1|2|32|64
}else{
    if(len(MODML)>=5){
        if(MODML[4]=="1"){
            //用户证书
            MODx509.KeyUsage=1|2|4|8|16
        }
        if(MODML[4]=="2"){
            //CA证书
            MODx509.KeyUsage=1|2|32|64
        }
        if(MODML[4]=="3"){
            //用户证书 仅用于加密 签名
            MODx509.KeyUsage=1|2|128
        }
        if(MODML[4]=="4"){
            //用户证书 仅用于解密 签名
            MODx509.KeyUsage=1|2|256
        }
    }
}

 if(MODML[1]=="initOCSP" || MODML[1]=="initTIMSTAMP"){
    MODx509.KeyUsage=1
 }
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
 nums := make([]int, 0) 
 //获取增强型密钥用法多个
 if(len(MODML)>=6){
    exoid:=MODML[5]
    if(exoid != "null"){
        if strings.Contains(exoid, ","){
            oidlistrow:=strings.Split(exoid, ",")
            for _, danduoid := range oidlistrow {
                num, _ := strconv.Atoi(danduoid)
                nums = append(nums, num)
            }
        }else{
             num, err := strconv.Atoi(exoid)  
             if err != nil {  
                 num=0
             }  
             
             nums = append(nums, num) 
        }
    }

 }
 xxxextKeyUsage := make([]x509.ExtKeyUsage, len(nums)) 
 for i, num := range nums {  
    xxxextKeyUsage[i] = x509.ExtKeyUsage(num)  
 }  
 MODx509.ExtKeyUsage=xxxextKeyUsage
 if(MODML[1]=="initOCSP"){
    MODx509.ExtKeyUsage=[]x509.ExtKeyUsage{9}
 }
 if(MODML[1]=="initTIMSTAMP"){
    MODx509.ExtKeyUsage=[]x509.ExtKeyUsage{8}
 }
 MODjiaqiangyongfa:=MODx509.ExtKeyUsage
 //MOD证书策略 
 MODPolicyIdentifiers := []asn1.ObjectIdentifier{
    {2,23,140,1,3},//EV扩展代码签名证书
    {2,23,140,1,1},         //EV扩展域名证书
    //{1,3,6,1,5,5,7,2,1},  //为CPS限定标识符
    //{1,3,6,1,5,5,7,2,2}, //为用户通告标识符

 }  
if(CertIsCA==true){
 MODPolicyIdentifiers = []asn1.ObjectIdentifier{
    {2,23,140,1,3},//EV扩展代码签名证书
    {2,23,140,1,1},         //EV扩展域名证书
    {2,5,29,32,0},  //所有颁发策略
    {1,3,6,1,4,1,311,10,12,1}, //所有应用策略

 }  
}

 //MOD添加其他增强型密钥用法 补充
 MODUnknownExtKeyUsage := []asn1.ObjectIdentifier{
 } 
if(len(MODML)>=11){
    if(MODML[10]=="1"){
 MODUnknownExtKeyUsage = []asn1.ObjectIdentifier{
   // asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,1},
     {1,3,6,1,4,1,311,10,3,5},  //windows硬件驱动验证
     {1,3,6,1,4,1,311,10,3,6},  //windows系统组件验证
     {1,3,6,1,4,1,311,10,3,7},  //OEMwindows系统组件验证
     {1,3,6,1,4,1,311,10,3,8},  //内嵌windows系统组件验证

 }  
    }
}
 //******************************
 // 定义时间格式  不用动我
 modlayout := "2006/01/02-15:04:05"  
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
if(MODML[1]=="initOCSP" || MODML[1]=="initTIMSTAMP"){
    MODUnknownExtKeyUsage = []asn1.ObjectIdentifier{}
    MODatime=time.Now()// "2006/01/02-15:04:05" 
    MODbtime=time.Now().Add(time.Hour * 24 * 365)
} 
//*********************************

//MOD***********************
 // 创建证书模板  
 template := x509.Certificate{  
     SerialNumber: big.NewInt(CERTID),  
     Subject: MODname,
     NotBefore: MODatime, // 证书生效时间  
     NotAfter:  MODbtime, // 证书过期时间
     
     KeyUsage:MODyongtu, // 密钥用途 
     

     ExtKeyUsage:MODjiaqiangyongfa,//增强密钥用法

    //MOD 重点 补充其他增强型密钥用法  例如{2.2.4.4},{1.2.3.4}
    UnknownExtKeyUsage:MODUnknownExtKeyUsage,

    SignatureAlgorithm:MODsuanfa, 

    BasicConstraintsValid: true,
    IsCA: CertIsCA,// 非CA证书的基本约束有效，用于限制证书的使用范围 
    //MaxPathLen:3,//证书链最大层次,默认不启用该参数，使用去开头注释符


    
    AuthorityKeyId:priid,//颁发者密钥标识符
    SubjectKeyId:subid,//使用者密钥标识符

    //颁发者信息访问
    OCSPServer:MODissureocsp,//ocsp在线证书协议URL地址
    IssuingCertificateURL:MODissurecrt,//颁发者证书URL地址
    CRLDistributionPoints:MODissurecrl,//颁发者注销列表URL地址
    //使用者可选名称
    DNSNames:MODuseyuming,//可选域名
    EmailAddresses:MODuseemail,//可选邮箱
    IPAddresses:MODuseip,//可选ip
    /* 
    URIs :[]*url.URL{  
     {Scheme: "http", Host: "aaa.com"},   //新规：限定URL使用 默认不启用
     {Scheme: "https", Host: "bbb.com"},  
     {Scheme: "ftp", Host: "ccc.org"},  
     }, 
     */
    PolicyIdentifiers:MODPolicyIdentifiers,//证书策略CPS
    //名称限制严格 名称约束
    /*
    PermittedDNSDomainsCritical:true, //新规：严格限制域名 true 和false默认不启用
    PermittedDNSDomains:[]string{"q1.com"},//新规：严格允许域名使用 默认不启用
    ExcludedDNSDomains:[]string{"q2.com"},// 新规：严格禁止子域名使用 默认不启用
    */
}



    /*
    // 创建一个CT预证书扩展
    ctyExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
        Critical: true, //预证书这个必须为true
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
    
    noocspExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1,3,6,1,5,5,7,48,1,5},
        Critical: false,
        Value:    []byte{0x05,0x00},
    }
    /*
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
     // 创建一个关键增强型密钥用法扩展 时间戳专用
    modgjExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{2, 5, 29,37},
        Critical: true,
        Value:[]byte{0x30,0x0A,0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x08},
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
    if(MODML[1]=="initOCSP"){
    template.ExtraExtensions = []pkix.Extension{
        caverExtension,
        //ctyExtension,
        //ctExtension,
        noocspExtension,
        //ocspmustExtension,
        //cpsExtension,
        }
    }
if(MODML[1]=="initTIMSTAMP"){
    template.ExtraExtensions = []pkix.Extension{
        caverExtension,
        modgjExtension,
        //ctyExtension,
        //ctExtension,
        //noocspExtension,
        //ocspmustExtension,
        //cpsExtension,
        }
} 
 // 使用证书模板和RSA密钥对生成证书  
 certderBytes, err := x509.CreateCertificate(rand.Reader, &template, rootcert, &certprivateKey.PublicKey, rootkey)  
 if err != nil {  
 fmt.Println("cert证书生成失败：", err)  
 return  
 }  

if(MODML[1]=="initTIMSTAMP" && MODML[2]=="SHA1"){
     // 将证书保存到文件  
     certOut, err := os.Create(TSACERTsha1crt)  
     if err != nil {  
     fmt.Println("SHA1 TSA签名专用证书无法创建证书文件：", err)  
     return  
     }  
     pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certderBytes})  
     certOut.Close()  
     fmt.Println("SHA1 TSA专用证书生成成功！")  
      savePrivateKey(certprivateKey,TSACERTsha1key)
}
if(MODML[1]=="initTIMSTAMP" && MODML[2]=="SHA256"){
     // 将证书保存到文件  
     certOut, err := os.Create(TSACERTsha256crt)  
     if err != nil {  
     fmt.Println("SHA256 TSA签名专用证书无法创建证书文件：", err)  
     return  
     }  
     pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certderBytes})  
     certOut.Close()  
     fmt.Println("SHA256 TSA专用证书生成成功！")  
      savePrivateKey(certprivateKey,TSACERTsha256key)
}

if(MODML[1]=="initOCSP"){
     // 将证书保存到文件  
     certOut, err := os.Create(MODTC+"\\PKI\\OCSP\\ocsp.crt")  
     if err != nil {  
     fmt.Println("OCSP专用证书无法创建证书文件：", err)  
     return  
     }  
     pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certderBytes})  
     certOut.Close()  
     fmt.Println("OCSP专用证书生成成功！")  
      savePrivateKey(certprivateKey,MODTC+"\\PKI\\OCSP\\ocsp.key")
}
if(MODML[1] != "initTIMSTAMP" && MODML[1] != "initOCSP"){
     // 将证书保存到文件  
     certOut, err := os.Create(MODPKI_certdir+template.SerialNumber.Text(16)+".crt")  
     if err != nil {  
     fmt.Println("用户证书CRT无法创建证书文件：", err)  
     return  
     }  
     pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certderBytes})  
     certOut.Close()  
     fmt.Println("用户证书CRT证书生成成功！")  
}

 




 // 将证书保存到文件  
 certOut2, err := os.Create(MODTC+"\\PKI\\WebPublic\\CRT\\"+template.SerialNumber.Text(16)+".crt")  
 if err != nil {  
 fmt.Println("WebPublic证书副本无法创建证书文件：", err)  
 return  
 }  
 pem.Encode(certOut2, &pem.Block{Type: "CERTIFICATE", Bytes: certderBytes})  
 certOut2.Close()  
 fmt.Println("WebPublic证书副本生成成功！")  

    savePrivateKey(certprivateKey,MODPKI_keydir +template.SerialNumber.Text(16)+".key")
    ags:=[]string {"newcert",template.SerialNumber.Text(16),"E", "V","0"}
    if(CertIsCA==true){
      ags=[]string {"newcert",template.SerialNumber.Text(16),"C", "V","0"}  
    }
    cmd3:=exec.Command(MODAUTOEXE, ags...)  
    outtext,err:=cmd3.CombinedOutput() 
    if err != nil {
        fmt.Println("添加数据出错了")
    }
    if(string(outtext)!=""){
        fmt.Println(string(outtext))
    }



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