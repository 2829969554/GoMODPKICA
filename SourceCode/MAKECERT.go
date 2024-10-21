package main  
  //配置文件位于PKI\CONFIG.txt
  //MODCA2     2024/10/20 19:07
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
     可填null空  Issure  参数11(颁发者序列号)
     可填RSA默认 CertKeyalgorithm  参数12(需求密钥类型)   例如 RSA,ECC,SM2 
例如全null 命令:makecert CN=test null null null null null null null null null RSA
                全null 意思是生成一个CN为test的sha1的1024位的全功能用户证书（无增强密钥用法）无特定用法，有效期1年支持吊销
例如SSL域名 makecert CN=test.com 2048 sha256 0 1,2 0 1 test.com null RSA
            这行意思是生成一个2048位sha256的用户DV 域名 SSL证书 全功能，增强用法是服务器验证客户端验证 有效期1年
           makecert CN=127.0.0.1 2048 sha256 0 1,2 0 1 null 127.0.0.1 null RSA
           这行意思是生成一个2048位sha256的用户DV IP SSL证书 全功能，增强用法是服务器验证客户端验证 有效期1年
例如代码签名 EV代码签名 makecert CN=我是EV证书,O=中国公司,OU=研发部,EVCT=CN,EVCITY=BEIJING,EVTYPE=PrivateBank 2048 sha256 0 3 0 1 null null 1 RSA
            带有EV扩展标识支持驱动
            。。。。扩展性很强。。这里就不举例子了
             */
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
 "io/ioutil"
 "log"
 mrand "math/rand"
"modcrypto/gm/sm2"
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

fmt.Println("执行参数",MODML)

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
MODPKI_WebPublicCRTdir:=MODTC+"\\PKI\\WebPublic\\CRT\\"

MODPKI_ocspdir:=MODTC+"\\PKI\\OCSP\\"


MODPKI_rootdir:=MODTC+"\\PKI\\ROOT\\" 
MODPKI_cadir:=MODTC+"\\PKI\\CA\\" 
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


 var RSArootprivateKey *rsa.PrivateKey
 var ECCrootprivateKey *ecdsa.PrivateKey
 var SM2rootprivateKey *sm2.PrivateKey

//MOD 解码颁发者证书和颁发者私钥
banfazheid:="root"
banfazhepath:=""

//使用者|颁发者  目标签名类型分别有三种  RSA ECC SM2
//默认初始化RSA
CertKeyalgorithm:="RSA" 
RootKeyalgorithm:="RSA"


if(len(MODML)>=13){
    CertKeyalgorithm=MODML[12]
}

if(MODML[1] == "initOCSP"){
   CertKeyalgorithm=MODML[2]
}

if(MODML[1] == "initTIMSTAMP"){
    CertKeyalgorithm=MODML[3]
}

fmt.Println("使用者的证书签发类型",CertKeyalgorithm)

if(len(MODML)>=12){
    banfazheid=MODML[11]
}
if(banfazheid!="root"){
    _, err := os.Stat(MODPKI_cadir+banfazheid+".crt") 
    if os.IsNotExist(err) {  
        //不存在
       banfazhepath= MODPKI_rootdir+"root"
     } else {  
        //存在
         banfazhepath= MODPKI_cadir+banfazheid
     }  
}else{
   banfazhepath= MODPKI_rootdir+"root" 
}

 // 读取证书文件  
 rootPEM, err := ioutil.ReadFile(banfazhepath+".crt")  
 if err != nil {  
 log.Fatalf("无法读取证书文件：%v", err)  
 }  
 //fmt.Println(string(certPEM))
 // 读取私钥文件  
 rootkeyPEM, err := ioutil.ReadFile(banfazhepath+".key")  
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

 // 加载证书和私钥  
 rootcert, err := sm2x509.ParseCertificate(crtblock.Bytes)  
 if(err != nil  && CertKeyalgorithm != "SM2"){  
    log.Fatalf("无法解析RSA/ECC证书：%v", err)  
 }  

 // 解码SM2证书和私钥  
 sm2rootcert, sm2err := sm2x509.ParseCertificate(crtblock.Bytes)  
 if sm2err != nil {  
    log.Fatalf("无法解析SM2证书：%v", err)  
 }  




if(keyblock.Type == "RSA PRIVATE KEY"){
    if keyblock == nil || keyblock.Type != "RSA PRIVATE KEY" {  
     log.Fatal("无效的RSA KEY")  
     } 
     rootkey, err := x509.ParsePKCS1PrivateKey(keyblock.Bytes)  
     if err != nil {  
     fmt.Println("无法解析RSA私钥：%v", err)  
     } 
     RootKeyalgorithm = "RSA"
     RSArootprivateKey = rootkey  
}
if(keyblock.Type == "EC PRIVATE KEY"){
    if keyblock == nil || keyblock.Type != "EC PRIVATE KEY" {  
     log.Fatal("无效的ECC KEY")  
     }  
     rootkey, err := x509.ParseECPrivateKey(keyblock.Bytes)  
     if err != nil {  
     fmt.Println("无法解析ECC私钥：%v", err)  
     } 
     RootKeyalgorithm = "ECC"
     ECCrootprivateKey = rootkey  
}

if(keyblock.Type == "SM2 PRIVATE KEY"){
    if keyblock == nil || keyblock.Type != "SM2 PRIVATE KEY" {  
     log.Fatal("无效的SM2 KEY")  
     } 
     rootkey, err := sm2.ParsePrivateKey(keyblock.Bytes)
     if err != nil {  
     fmt.Println("无法解析SM2私钥：%v", err)  
     } 
     RootKeyalgorithm = "SM2"
     SM2rootprivateKey = rootkey
}

fmt.Println("颁发者的证书类型",RootKeyalgorithm)


 var RSAcertprivateKey *rsa.PrivateKey
 var ECCcertprivateKey *ecdsa.PrivateKey
 var SM2certprivateKey *sm2.PrivateKey

 //MOD***************************
 MODx509:=sm2x509.Certificate{}
 MODname := pkix.Name{}  
 //使用者信息参数




  // 使用逗号分隔字符串  
 substrings := strings.Split(MODML[1], ",") 

  
var certkeybit int
if(MODML[1]=="initOCSP" || MODML[1]=="initTIMSTAMP"){
         if(CertKeyalgorithm == "RSA"){
            certkeybit=2048
         }
         if(CertKeyalgorithm == "ECC"){
            certkeybit=256
         }
         if(CertKeyalgorithm == "SM2"){
            certkeybit=256
         }
}else{
    certkeybit,err=strconv.Atoi(MODML[2]) 
     if err != nil {
         //如果rootkeybit为空 默认密钥位数
         if(CertKeyalgorithm == "RSA"){
            certkeybit=2048
         }
         if(CertKeyalgorithm == "ECC"){
            certkeybit=256
         }
         if(CertKeyalgorithm == "SM2"){
            certkeybit=256
         }
     }
} 



     //防止输入的密钥位数超出范围 RSA:1024 - 8192  ECC 224 256 384 521  SM2 256
     if(CertKeyalgorithm == "RSA"){
        if(certkeybit < 1024){
            certkeybit=1024
        }
     }

     if(CertKeyalgorithm == "ECC"){
        if(certkeybit <= 256){
            certkeybit=256
        }

        if(certkeybit > 256 && certkeybit <= 384){
            certkeybit=384
        }
        if(certkeybit > 384){
            certkeybit=521
        }
     }

     //SM2密钥长度只有256
     if(CertKeyalgorithm == "SM2"){
        certkeybit=256
     }

 roothash :=MODx509.SignatureAlgorithm

if(MODML[1] != "initOCSP" && MODML[1] != "initTIMSTAMP"){
    switch MODML[3] {  
    case "sha1":  
        roothash=3
        if(RootKeyalgorithm=="ECC"){
           roothash=9 
        }
    case "sha256":  
        roothash=4 
        if(RootKeyalgorithm=="ECC"){
           roothash=10 
        }
    case "sha384":  
        roothash=5
        if(RootKeyalgorithm=="ECC"){
           roothash=11 
        }
    case "sha512":  
        roothash=6
        if(RootKeyalgorithm=="ECC"){
           roothash=12 
        }
    case "SHA256RSAPSS":  
        roothash=13 
    case "SHA384RSAPSS":  
        roothash=14 
    case "SHA512RSAPSS":  
        roothash=15 
    case "SM3":  
        roothash=0
    default:  
        roothash=3
    }
}

/*
if(MODML[1] == "initOCSP" || MODML[1] == "initTIMSTAMP"){
        if(CertKeyalgorithm=="ECC"){
           roothash=10 
        }
        if(CertKeyalgorithm=="RSA"){
           roothash=3 
        }
}
*/


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
            fmt.Println("未知主题信息:", substring)  
        }  
 }


 
 //MOD密钥位数
 MODKbit:=certkeybit

if(MODML[1]=="initOCSP" || MODML[1] == "initTIMSTAMP"){
    if(CertKeyalgorithm == "RSA"){
        MODKbit=2048 
        roothash=3 
    }
    if(CertKeyalgorithm == "ECC"){
        MODKbit=256 
        roothash=10 
    }
    if(CertKeyalgorithm == "SM2"){
        MODKbit=256
    }
    MODname = pkix.Name{} 
    MODname.CommonName = rootcert.Subject.CommonName+" By OCSP"
    MODname.Organization=rootcert.Subject.Organization
    MODname.OrganizationalUnit= []string{"Only OCSP Signing"} 
    if(MODML[1] == "initTIMSTAMP" && MODML[2] == "SHA1"){

        if(CertKeyalgorithm=="ECC"){
           roothash=9 
        }
        if(CertKeyalgorithm=="RSA"){
           roothash=3 
        }

        MODname.OrganizationalUnit= []string{"Only TSA SHA1 Signing"} 
        MODname.CommonName = rootcert.Subject.CommonName+" By Timstamp SHA1"
    }
    if(MODML[1] == "initTIMSTAMP" && MODML[2] == "SHA256"){

        if(CertKeyalgorithm=="ECC"){
           roothash=10 
        }
        if(CertKeyalgorithm=="RSA"){
           roothash=4 
        }

        MODname.OrganizationalUnit= []string{"Only TSA SHA256 Signing"} 
        MODname.CommonName = rootcert.Subject.CommonName+" By Timstamp SHA256"
    }
}



fmt.Println("密钥长度：",MODKbit)  

if(CertKeyalgorithm =="RSA"){
     // 生成RSA密钥对  
     certprivateKey, err := rsa.GenerateKey(rand.Reader, MODKbit)  
     if err != nil {  
        fmt.Println("RSA 密钥对生成失败：", err)  
        return  
     } 
     RSAcertprivateKey = certprivateKey
}

if(CertKeyalgorithm =="SM2"){
     // 生成SM2密钥对  
     sm2privateKey, err := sm2.GenerateKey(rand.Reader)  
     if err != nil {  
        fmt.Println("SM2 密钥对生成失败：", err)  
        return  
     }
     SM2certprivateKey = sm2privateKey
} 

if(CertKeyalgorithm =="ECC"){
    if(MODKbit == 224){
        eccprivateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
        if err != nil {  
           fmt.Println("ECC 密钥对生成失败：", err)  
           return  
        }
        ECCcertprivateKey = eccprivateKey        
    }
    if(MODKbit == 256){
        eccprivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
        if err != nil {  
           fmt.Println("ECC 密钥对生成失败：", err)  
           return  
        }
        ECCcertprivateKey = eccprivateKey        
    }
    if(MODKbit == 384){
        eccprivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
        if err != nil {  
           fmt.Println("ECC 密钥对生成失败：", err)  
           return  
        }
        ECCcertprivateKey = eccprivateKey
     
    }
    if(MODKbit == 521){
        eccprivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
        if err != nil {  
           fmt.Println("ECC 密钥对生成失败：", err)  
           return  
        } 
        ECCcertprivateKey = eccprivateKey     
    }
}







// 提取root公钥  将公钥转换为[]byte 
 var rootpublicKeyDER []byte
// 提取cert公钥  将公钥转换为[]byte 
 var certpublicKeyDER []byte

if(RootKeyalgorithm =="RSA"){
     rootpublicKey := &RSArootprivateKey.PublicKey 
     rootpublicKeyDERtmp, _ := x509.MarshalPKIXPublicKey(rootpublicKey) 
     rootpublicKeyDER = rootpublicKeyDERtmp
}
if(CertKeyalgorithm =="RSA"){
     certpublicKey := &RSAcertprivateKey.PublicKey 
     certpublicKeyDERtmp, _ := x509.MarshalPKIXPublicKey(certpublicKey)  
     certpublicKeyDER = certpublicKeyDERtmp
}

if(RootKeyalgorithm =="ECC"){
    rootpublicKey := &ECCrootprivateKey.PublicKey 
    rootpublicKeyDERtmp, _ := x509.MarshalPKIXPublicKey(rootpublicKey) 
    rootpublicKeyDER = rootpublicKeyDERtmp
}
if(CertKeyalgorithm =="ECC"){
     certpublicKey := &ECCcertprivateKey.PublicKey 
     certpublicKeyDERtmp, _ := x509.MarshalPKIXPublicKey(certpublicKey)  
     certpublicKeyDER = certpublicKeyDERtmp
}

if(RootKeyalgorithm =="SM2"){
    rootpublicKey := &SM2rootprivateKey.PublicKey
    rootpublicKeyDERtmp, _ := sm2.MarshalPublicKey(rootpublicKey)
    rootpublicKeyDER = rootpublicKeyDERtmp
}
if(CertKeyalgorithm =="SM2"){
    certpublicKey := &SM2certprivateKey.PublicKey 
    certpublicKeyDERtmp, _ := sm2.MarshalPublicKey(certpublicKey)   
    certpublicKeyDER = certpublicKeyDERtmp
}



 //MOD颁发者密钥
 var arr,arr2 []byte  

 hash1 := sha256.New()
 hash1.Write(rootpublicKeyDER)

 hash2 := sha256.New()
 hash2.Write(certpublicKeyDER)

 arr  = hash1.Sum(nil)
 arr2 = hash2.Sum(nil)
 //颁发者密钥sha1
 priid:=arr[:]
 //使用者密钥sha1
 subid:=arr2[:]
 //证书序列号
 CERTID:=time.Now().Unix()  + int64(mrand.Intn(1000))
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
   if(len(MODML)>=8){
    txtime:=MODML[7]
        if(len(txtime)<5){
            qishin:=1
            if(txtime!="null"){
                qishin,err=strconv.Atoi(txtime)
                if err != nil {
                    qishin=1
                }
            }
            modqianfaTime = time.Now().UTC().Format("2006/01/02-15:04:05")
            modguoqiTime=time.Now().UTC().Add(time.Hour * 24 * 365 * time.Duration(qishin)).Format("2006/01/02-15:04:05")
        }else{
            result := strings.Split(txtime,"T")  
            if(len(result)==2){
               modqianfaTime=result[0] 
               modguoqiTime=result[1] 
            }
        }

   }
 }

 //通过证书类型决定序列号的组成
 if(CertIsCA){
    //CA类型证书序列号合成
    CERTID = 507780148300837 + CERTID
 }else{
    //用户类型证书序列号合成
    CERTID = 2829969554 + CERTID
 }

//MOD授权者信息
MODSUCRT=strings.Replace(MODSUCRT, "{CID}", rootcert.SerialNumber.Text(16), -1)
MODSUCRL=strings.Replace(MODSUCRL, "{CID}", rootcert.SerialNumber.Text(16), -1)
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

 MODsuanfa:=MODx509.SignatureAlgorithm

 if(RootKeyalgorithm != "SM2"){
    MODx509.SignatureAlgorithm=roothash
    MODsuanfa=MODx509.SignatureAlgorithm
 }

 //fmt.Println(MODsuanfa)
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
 MODx509.ExtKeyUsage=[]sm2x509.ExtKeyUsage{}
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
 xxxextKeyUsage := make([]sm2x509.ExtKeyUsage, len(nums)) 
 for i, num := range nums {  
    xxxextKeyUsage[i] = sm2x509.ExtKeyUsage(num)  
 }  
 MODx509.ExtKeyUsage=xxxextKeyUsage
 if(MODML[1]=="initOCSP"){
    MODx509.ExtKeyUsage=[]sm2x509.ExtKeyUsage{9}
 }
 if(MODML[1]=="initTIMSTAMP"){
    MODx509.ExtKeyUsage=[]sm2x509.ExtKeyUsage{8}
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
 template := sm2x509.Certificate{  
     SerialNumber: big.NewInt(CERTID),  
     Subject: MODname,
     NotBefore: MODatime.UTC(), // 证书生效时间  
     NotAfter:  MODbtime.UTC(), // 证书过期时间
     
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
*/

    //定义SCT结构体
    var mysct,mysct2 SCT
    //版本号
    mysct.Version = 0
    mysct2.Version = 0
    //证书透明度日志ID
    mysct.LogID = subid
    mysct2.LogID = priid
    //签署实时数据戳UTC时间，精确到毫秒
    mysct.Timestamp = uint64(time.Now().UTC().UnixMilli())
    mysct2.Timestamp = uint64(time.Now().UTC().UnixMilli())
    //等待签名数据的哈希算法 0:none  1:MD5  2:SHA1  3:SHA224  4:SHA256   5:SHA384  6:SHA512
    mysct.Hash = 4
    mysct2.Hash = 4
    //签名算法 0:anonymous  1:RSA  2:DSA  3:ECDSA
    mysct.Signtype = 3
    mysct2.Signtype = 3
    //签名内容
    mysct.Signature = SCTGenerateSignature()
    mysct2.Signature = SCTGenerateSignature()
    //fmt.Println("长度",len(mysct.Signature))
    //根据上述参数创建SCT结构数据
    mysct.CreateSCT()
    mysct2.CreateSCT()

    //定义并创建SCT列表结构体数据
    var mysctlist SCTList
    mysctlist = SCTList{
        //将2组SCT结构套在一起
        SCTs: []SCT{mysct,mysct2},
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
    cpsTEXT:= `我是可信证书`

    cpsExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{2,5,29,32},
        Critical: false,
        Value:    GenerateCPSbyte([]asn1.ObjectIdentifier{{2,23,140,1,4,1},{2,23,140,1,4,2}},cpsURL,cpsTEXT),
    }  
    // 创建一个OCSP不撤销检查扩展
    
    noocspExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1,3,6,1,5,5,7,48,1,5},
        Critical: false,
        Value:    []byte{0x05,0x00},
    }
    
    // 创建一个OCSP MUST装订扩展
   /* ocspmustExtension := pkix.Extension{
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
        cpsExtension,
        }
    if(MODML[1]=="initOCSP"){
    template.ExtraExtensions = []pkix.Extension{
        caverExtension,
        //ctyExtension,
        //ctExtension,
        noocspExtension,
        //ocspmustExtension,
        cpsExtension,
        }
    }
    //密钥用法为域名SSL 且不是CA，必须为最终实体 增加CT透明度
    if(CertIsCA==false && len(MODML) >= 6){
        if strings.Contains(MODML[5], "1") || strings.Contains(MODML[5], "2"){
            template.ExtraExtensions=append(template.ExtraExtensions,ctExtension)
            //template.ExtraExtensions=append(template.ExtraExtensions,ocspmustExtension)
        }
    }
if(MODML[1]=="initTIMSTAMP"){
    template.ExtraExtensions = []pkix.Extension{
        caverExtension,
        modgjExtension,
        //ctyExtension,
        ctExtension,
        //noocspExtension,
        //ocspmustExtension,
        cpsExtension,
        }
} 
 // 使用证书模板和RSA密钥对生成证书  
/* 颁发者  使用者组合，交叉签发证书实现
1: RSA  RSA   2.RSA ECC  3.RSA SM2
2: ECC  RSA   2.ECC ECC  3.ECC SM2
3: SM2  RSA   2.SM2 ECC  3.SM2 SM2
*/
var certderBytes []byte
//第一组组合
if(RootKeyalgorithm == "RSA"){

    if(CertKeyalgorithm =="RSA"){
     certderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, rootcert, &RSAcertprivateKey.PublicKey, RSArootprivateKey)  
     if err != nil {  
        fmt.Println("RSA-RSA cert证书生成失败：", err)  
        return  
     } 
     certderBytes = certderBytestmp 
    }

    if(CertKeyalgorithm =="ECC"){
     certderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, rootcert, &ECCcertprivateKey.PublicKey, RSArootprivateKey)  
     if err != nil {  
        fmt.Println("RSA-ECC cert证书生成失败：", err)  
        return  
     } 
     certderBytes = certderBytestmp 
    }

    if(CertKeyalgorithm =="SM2"){
     certderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, sm2rootcert, &SM2certprivateKey.PublicKey, RSArootprivateKey)  
     if err != nil {  
        fmt.Println("RSA-SM2 cert证书生成失败：", err)  
        return  
     } 
     certderBytes = certderBytestmp 
    }
}


//第二组组合
if(RootKeyalgorithm == "ECC"){
    if(CertKeyalgorithm =="RSA"){
     certderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, rootcert, &RSAcertprivateKey.PublicKey, ECCrootprivateKey)  
     if err != nil {  
        fmt.Println("ECC-RSA cert证书生成失败：", err)  
        return  
     } 
     certderBytes = certderBytestmp 
    }

    if(CertKeyalgorithm =="ECC"){
     certderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, rootcert, &ECCcertprivateKey.PublicKey, ECCrootprivateKey)  
     if err != nil {  
        fmt.Println("ECC-ECC cert证书生成失败：", err)  
        return  
     } 
     certderBytes = certderBytestmp 
    }

    if(CertKeyalgorithm =="SM2"){
     certderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, sm2rootcert, &SM2certprivateKey.PublicKey, ECCrootprivateKey)  
     if err != nil {  
        fmt.Println("ECC-SM2 cert证书生成失败：", err)  
        return  
     } 
     certderBytes = certderBytestmp 
    }
    
}
//第三组组合
if(RootKeyalgorithm == "SM2"){
    if(CertKeyalgorithm =="RSA"){
     certderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, rootcert, &RSAcertprivateKey.PublicKey, SM2rootprivateKey)  
     if err != nil {  
        fmt.Println("SM2-RSA cert证书生成失败：", err)  
        return  
     } 
     certderBytes = certderBytestmp 
    }

    if(CertKeyalgorithm =="ECC"){
     certderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, rootcert, &ECCcertprivateKey.PublicKey, SM2rootprivateKey)  
     if err != nil {  
        fmt.Println("SM2-ECC cert证书生成失败：", err)  
        return  
     } 
     certderBytes = certderBytestmp 
    }

    if(CertKeyalgorithm =="SM2"){
     certderBytestmp, err := sm2x509.CreateCertificate(rand.Reader, &template, sm2rootcert, &SM2certprivateKey.PublicKey, SM2rootprivateKey)  
     if err != nil {  
        fmt.Println("SM2-SM2 cert证书生成失败：", err)  
        return  
     } 
     certderBytes = certderBytestmp 
    }
    
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
      
      if(CertKeyalgorithm =="RSA"){
        saveRSAPrivateKey(RSAcertprivateKey,TSACERTsha1key)
      }
      if(CertKeyalgorithm =="ECC"){
        saveECCPrivateKey(ECCcertprivateKey,TSACERTsha1key)
      }
      if(CertKeyalgorithm =="SM2"){
        saveSM2PrivateKey(SM2certprivateKey,TSACERTsha1key)
      }
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
       if(CertKeyalgorithm =="RSA"){
        saveRSAPrivateKey(RSAcertprivateKey,TSACERTsha256key)
      }
      if(CertKeyalgorithm =="ECC"){
        saveECCPrivateKey(ECCcertprivateKey,TSACERTsha256key)
      }
      if(CertKeyalgorithm =="SM2"){
        saveSM2PrivateKey(SM2certprivateKey,TSACERTsha256key)
      }
}

if(MODML[1]=="initOCSP"){
     // 将证书保存到文件  

     certOut, err := os.Create(MODPKI_ocspdir+"ocsp.crt")  
     if err != nil {  
     fmt.Println("OCSP专用证书无法创建证书文件：", err)  
     return  
     }  
     pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certderBytes})  
     certOut.Close()  
     fmt.Println("OCSP专用证书生成成功！")  
  
      if(CertKeyalgorithm =="RSA"){
        saveRSAPrivateKey(RSAcertprivateKey,MODPKI_ocspdir+"ocsp.key")
      }
      if(CertKeyalgorithm =="ECC"){
        saveECCPrivateKey(ECCcertprivateKey,MODPKI_ocspdir+"ocsp.key")
      }
      if(CertKeyalgorithm =="SM2"){
        saveSM2PrivateKey(SM2certprivateKey,MODPKI_ocspdir+"ocsp.key")
      }
}
if(MODML[1] != "initTIMSTAMP" && MODML[1] != "initOCSP" && CertIsCA==false){
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

if(CertIsCA==true){
     // 将证书保存到文件  
     certOut, err := os.Create(MODPKI_cadir+template.SerialNumber.Text(16)+".crt")  
     if err != nil {  
     fmt.Println("用户证书CRT无法创建证书文件：", err)  
     return  
     }  
     pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certderBytes})  
     certOut.Close()  
     fmt.Println("用户证书CRT证书生成成功！")    
} 




 // 将证书保存到文件  
 certOut2, err := os.Create(MODPKI_WebPublicCRTdir+template.SerialNumber.Text(16)+".crt")  
 if err != nil {  
 fmt.Println("WebPublic证书副本无法创建证书文件：", err)  
 return  
 }  
 pem.Encode(certOut2, &pem.Block{Type: "CERTIFICATE", Bytes: certderBytes})  
 certOut2.Close()  
 fmt.Println("WebPublic证书副本生成成功！")  

var ags []string
    if(CertIsCA==true){

      ags=[]string {"newcert",template.SerialNumber.Text(16),"C", "V","0","null",rootcert.SerialNumber.Text(16),CertKeyalgorithm}  

      if(CertKeyalgorithm =="RSA"){
        saveRSAPrivateKey(RSAcertprivateKey,MODPKI_cadir +template.SerialNumber.Text(16)+".key")
      }
      if(CertKeyalgorithm =="ECC"){
        saveECCPrivateKey(ECCcertprivateKey,MODPKI_cadir +template.SerialNumber.Text(16)+".key")
      }
      if(CertKeyalgorithm =="SM2"){
        saveSM2PrivateKey(SM2certprivateKey,MODPKI_cadir +template.SerialNumber.Text(16)+".key")
      }

    }else{



       if(CertKeyalgorithm =="RSA"){
        saveRSAPrivateKey(RSAcertprivateKey,MODPKI_keydir +template.SerialNumber.Text(16)+".key")
      }
      if(CertKeyalgorithm =="ECC"){
        saveECCPrivateKey(ECCcertprivateKey,MODPKI_keydir +template.SerialNumber.Text(16)+".key")
      }
      if(CertKeyalgorithm =="SM2"){
        saveSM2PrivateKey(SM2certprivateKey,MODPKI_keydir +template.SerialNumber.Text(16)+".key")
      }

    ags=[]string {"newcert",template.SerialNumber.Text(16),"E", "V","0","null",rootcert.SerialNumber.Text(16),CertKeyalgorithm} 
    }

    cmd3:=exec.Command(MODAUTOEXE, ags...)  
    outtext,err:=cmd3.CombinedOutput() 
    if err != nil {
        fmt.Println("添加数据出错了")
    }
    
    if(len(outtext) > 0){
        fmt.Println(string(outtext))
    }
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