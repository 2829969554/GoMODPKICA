package main  
  
import (  
 "crypto/rand"  
 "crypto/x509" 
 "crypto/x509/pkix"
 "math/big" 
 "encoding/pem"  
 "encoding/binary"
 "fmt"  
 "os"
 "encoding/asn1"
 "io/ioutil" 
 "time"
 "log"  
 "path/filepath"
 "strings"
 "strconv"
 "bufio" 
 //"modcrypto/gm/sm2"
 "crypto/rsa"  
 "crypto/ecdsa"
 //"modcrypto/hash/sm3"
 "tjfoc/gmsm/sm2"
 sm2x509 "tjfoc/gmsm/x509"
)  
  
func main() {
 ex, err := os.Executable()  
 if err != nil {  
 panic(err)  
 }  
//当前执行目录
MODTC:= filepath.Dir(ex)  
//所有证书记录表
MODPKI_certsfile:=MODTC+"\\PKI\\CERTS.txt"

//特定目录
MODPKI_rootdir:=MODTC+"\\PKI\\ROOT\\"
MODPKI_cadir:=MODTC+"\\PKI\\CA\\"
MODPKI_WEBcrldir:=MODTC+"\\PKI\\WebPublic\\CRL\\"

//********遍历颁发者证书
    // 打开文件  
    file, err := os.Open(MODPKI_certsfile)  
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

        clist:=strings.Split(line," ")
        if(len(clist) >= 6){
            if(clist[1]=="C" || clist[1]=="R"){
                modmakecrl(clist[1],clist[0],MODPKI_rootdir,MODPKI_cadir,MODPKI_WEBcrldir,MODPKI_certsfile,clist[6])
            }
        }
    } 


//**********

}

func modmakecrl(ctype string,IssureID string,MODPKI_rootdir string,MODPKI_cadir string,MODPKI_WEBcrldir string,MODPKI_certsfile string,Keytype string){
 // 读取证书文件  
 dqusepath:=""
 if(ctype=="R"){
    dqusepath=MODPKI_rootdir+"root"
 }
 if(ctype=="C"){
    dqusepath=MODPKI_cadir+IssureID
 }
 certPEM, err := ioutil.ReadFile(dqusepath+".crt")  
 if err != nil {  
    log.Fatalf("无法读取证书文件：%v", err)  
 }  
 //fmt.Println(string(certPEM))
 // 读取私钥文件  
 keyPEM, err := ioutil.ReadFile(dqusepath+".key")  
 if err != nil {  
    log.Fatalf("无法读取私钥文件：%v", err)  
 }  
  
 // 解码PEM证书  
 crtblock, _ := pem.Decode(certPEM)  
  if crtblock == nil || crtblock.Type != "CERTIFICATE"{  
    log.Fatal("无效的PEM证书")  
 }  
 // 解码PEM证书  
 keyblock, _ := pem.Decode(keyPEM) 

 // 解码RSA ECC证书和私钥  
 cert, err := x509.ParseCertificate(crtblock.Bytes)  

 if(err != nil  && Keytype != "SM2\r\n"){  
    log.Fatalf("无法解析RSA/ECC证书：%v", err)  
 }  

 // 解码SM2证书和私钥  
 sm2cert, sm2err := sm2x509.ParseCertificate(crtblock.Bytes)  
 if sm2err != nil {  
    log.Fatalf("无法解析SM2证书：%v", err)  
 }  

 var RSAprivatekey *rsa.PrivateKey
 var ECCprivatekey *ecdsa.PrivateKey
 var SM2privatekey *sm2.PrivateKey

 if(Keytype == "RSA\r\n"){
    if keyblock == nil || keyblock.Type != "RSA PRIVATE KEY" {  
        log.Fatal("无效的RSA KEY")  
    }
     key, err := x509.ParsePKCS1PrivateKey(keyblock.Bytes)  
     if err != nil {  
        fmt.Println("无法解析RSA私钥：%v", err)  
     }
     RSAprivatekey =  key
 }
 if(Keytype == "ECC\r\n"){
    if keyblock == nil || keyblock.Type != "EC PRIVATE KEY" {  
        log.Fatal("无效的ECC KEY")  
    } 
     key, err := x509.ParseECPrivateKey(keyblock.Bytes)  
     if err != nil {  
        fmt.Println("无法解析ECC私钥：%v", err)  
     }
    ECCprivatekey  =  key
 }
 if(Keytype == "SM2\r\n"){
    if keyblock == nil || keyblock.Type != "SM2 PRIVATE KEY" {  
        log.Fatal("无效的SM2 KEY")  
    } 
     key, err := sm2x509.ReadPrivateKeyFromPem(keyPEM,nil) //sm2.ParsePrivateKey(keyblock.Bytes)  
     if err != nil {  
        fmt.Println("无法解析SM2私钥：%v", err)  
     }
    SM2privatekey = key 
 }


  
 MODCERTLIST := []pkix.RevokedCertificate{}  
 //************************

 // 打开文本文件  
 file, err := os.Open(MODPKI_certsfile)  
 if err != nil {  
 fmt.Println("无法打开文件:", err)  
 return  
 }  
 defer file.Close()  
  
 // 创建一个Scanner来读取文件内容  
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
        
       // fmt.Println(line) // 输出这一行  
         // 使用空格分隔每行文本  
         fields := strings.Split(line," ")  
         // 输出分隔后的结果  
         //fmt.Println(fields[0],fields[2],fields[3])
         if(fields[2]=="R"){
             num2, err2 := strconv.Atoi(fields[3])  
             if err2 != nil {  
             fmt.Println("转换失败:", err2)  
             }  
             num, err := strconv.ParseInt(fields[0],16,64)  
             if err != nil {  
              fmt.Println("转换失败:", err)   
             }
             //fmt.Println(num)   
             //************
             // 定义一个日期时间字符串  
             dateTimeStr := rftrn(fields[4])
              
             // 使用time包中的Parse函数将字符串解析为time.Time类型  
             layout := "2006/01/02-15:04:05"
             parsedTime, err := time.Parse(layout, dateTimeStr)  
             if err != nil {  
                 fmt.Println("解析日期时间失败:", err)  
                 return  
             }  
              
                 revokedCert := pkix.RevokedCertificate{  
                     SerialNumber:   big.NewInt(int64(num)),  
                     RevocationTime: parsedTime.UTC(),  
                     Extensions: []pkix.Extension{  
                         {  
                         Id: asn1.ObjectIdentifier{2, 5, 29, 21},  
                         Critical: false,  
                         Value: []byte{0x0A, 0x01, byte(num2)},  
                         },  
                     },  
                 }  
  

        MODCERTLIST = append(MODCERTLIST, revokedCert) 

        
        } 
 
    } 


var csn []byte
 // 生成证书吊销列表（CRL）的签名请求（CSN）  
if(Keytype == "RSA\r\n"){
    csntmp, err := cert.CreateCRL(rand.Reader, RSAprivatekey,MODCERTLIST, time.Now().UTC().Add(-24*time.Hour), time.Now().UTC().Add(24*time.Hour)) // 假设吊销时间为24小时前到当前时间之间  
    if err != nil {  
        fmt.Println("RSA无法创建CRL签名请求：%v", err) 
        return 
    } 
    csn =  csntmp
}
if(Keytype == "ECC\r\n"){
    csntmp, err := cert.CreateCRL(rand.Reader, ECCprivatekey,MODCERTLIST, time.Now().UTC().Add(-24*time.Hour), time.Now().UTC().Add(24*time.Hour)) // 假设吊销时间为24小时前到当前时间之间  
    if err != nil {  
        fmt.Println("ECC无法创建CRL签名请求：%v", err) 
        return 
    } 
    csn =  csntmp
}

if(Keytype == "SM2\r\n"){
    csntmp, err := sm2cert.CreateCRL(rand.Reader, SM2privatekey,MODCERTLIST, time.Now().UTC().Add(-24*time.Hour), time.Now().UTC().Add(24*time.Hour)) // 假设吊销时间为24小时前到当前时间之间  
  
    if err != nil {  
        fmt.Println("SM2无法创建CRL签名请求：%v", err) 
        return 
    } 
    csn =  csntmp
}

 // 创建文件对象并打开文件以进行写入（如果文件不存在，则会创建该文件）  
 filecrlder, errder := os.Create(MODPKI_WEBcrldir+IssureID+".der.crl") // 假设将CRL保存为crl.pem文件  
 if errder != nil {  
fmt.Println("无法创建文件：%v", err)  
 }  
 defer filecrlder.Close()  
  
 // 将PEM格式的字节块写入文件（crl.pem）中  
 _, errder = filecrlder.Write(csn) // 将字节块写入文件，并忽略错误（如果有的话）  
 if errder != nil { // 如果出现错误，则记录错误并继续执行程序（如果有的话） 
   fmt.Println("无法写入文件：%v", err)
 }
  
 // 将签名请求转换为PEM格式的字节块  
 csnBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: csn})  
 if csnBytes == nil {  
 fmt.Println("无法将签名请求转换为PEM格式")  
 }  
  

 // 创建文件对象并打开文件以进行写入（如果文件不存在，则会创建该文件）  
 filecrl, err := os.Create(MODPKI_WEBcrldir+IssureID+".crl") // 假设将CRL保存为crl.pem文件  
 if err != nil {  
fmt.Println("无法创建文件：%v", err)  
 }  
 defer filecrl.Close()  
  
 // 将PEM格式的字节块写入文件（crl.pem）中  
 _, err = filecrl.Write(csnBytes) // 将字节块写入文件，并忽略错误（如果有的话）  
 if err != nil { // 如果出现错误，则记录错误并继续执行程序（如果有的话） 
   fmt.Println("无法写入文件：%v", err)
 }
     


//根备用CRLMODPKI_certsfile
if(ctype=="R"){
 // 创建文件对象并打开文件以进行写入（如果文件不存在，则会创建该文件）  
 filecrl, err := os.Create(MODPKI_WEBcrldir+"root.crl") // 假设将CRL保存为crl.pem文件  
 if err != nil {  
fmt.Println("无法创建文件：%v", err)  
 }  
 defer filecrl.Close()  
  
 // 将PEM格式的字节块写入文件（crl.pem）中  
 _, err = filecrl.Write(csnBytes) // 将字节块写入文件，并忽略错误（如果有的话）  
 if err != nil { // 如果出现错误，则记录错误并继续执行程序（如果有的话） 
   fmt.Println("无法写入文件：%v", err)
     }
}





}










//*************************函数声明区域***********************
func intToBytes(i int) []byte {  
    b := make([]byte, 4)  
    binary.BigEndian.PutUint32(b, uint32(i))  
    return b  
}

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