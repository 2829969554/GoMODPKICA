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
)  
  
func main() {  
 // 读取证书文件  
 certPEM, err := ioutil.ReadFile("root.crt")  
 if err != nil {  
 log.Fatalf("无法读取证书文件：%v", err)  
 }  
 //fmt.Println(string(certPEM))
 // 读取私钥文件  
 keyPEM, err := ioutil.ReadFile("private.key")  
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
if keyblock == nil || keyblock.Type != "RSA PRIVATE KEY" {  
 log.Fatal("无效的KEY证书")  
 }  

 // 解码证书和私钥  
 cert, err := x509.ParseCertificate(crtblock.Bytes)  
 if err != nil {  
 log.Fatalf("无法解析证书：%v", err)  
 }  
 key, err := x509.ParsePKCS1PrivateKey(keyblock.Bytes)  
 if err != nil {  
 fmt.Println("无法解析私钥：%v", err)  
 }  
  

revokedCert := pkix.RevokedCertificate{ 
    SerialNumber:   big.NewInt(1), // 吊销的证书序列号  
    RevocationTime: time.Now(),    // 吊销时间  
    // 吊销的扩展 
 Extensions:[]pkix.Extension{
    {
        Id: asn1.ObjectIdentifier{2, 5, 29, 21},
        Critical: false,  
        Value:[]byte{0x0A, 0x01, 0x05},
    },
    },
}

  

 // 生成证书吊销列表（CRL）的签名请求（CSN）  
 csn, err := cert.CreateCRL(rand.Reader, key,[]pkix.RevokedCertificate{revokedCert,revokedCert,}, time.Now().Add(-24*time.Hour), time.Now()) // 假设吊销时间为24小时前到当前时间之间  
 if err != nil {  
 fmt.Println("无法创建CRL签名请求：%v", err)  
 }  
  
 // 将签名请求转换为PEM格式的字节块  
 csnBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: csn})  
 if csnBytes == nil {  
 fmt.Println("无法将签名请求转换为PEM格式")  
 }  
  
 // 创建文件对象并打开文件以进行写入（如果文件不存在，则会创建该文件）  
 file, err := os.Create("root.crl") // 假设将CRL保存为crl.pem文件  
 if err != nil {  
fmt.Println("无法创建文件：%v", err)  
 }  
 defer file.Close()  
  
 // 将PEM格式的字节块写入文件（crl.pem）中  
 _, err = file.Write(csnBytes) // 将字节块写入文件，并忽略错误（如果有的话）  
 if err != nil { // 如果出现错误，则记录错误并继续执行程序（如果有的话） 
   fmt.Println("无法写入文件：%v", err)
     }
}

func intToBytes(i int) []byte {  
    b := make([]byte, 4)  
    binary.BigEndian.PutUint32(b, uint32(i))  
    return b  
}