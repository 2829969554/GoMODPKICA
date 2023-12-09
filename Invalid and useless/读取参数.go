package main  
  
import (  
 "crypto/x509"  
 "encoding/pem"  
 "fmt"  
 "io/ioutil"  
 "log"  
)  
  
func main() {  
 // 读取PEM证书文件  
 certPEM, err := ioutil.ReadFile("root.crt")  
 if err != nil {  
 log.Fatalf("无法读取证书文件：%v", err)  
 }  
  
 // 解码PEM证书  
 block, _ := pem.Decode(certPEM)  
 if block == nil || block.Type != "CERTIFICATE" {  
 log.Fatal("无效的PEM证书")  
 }  
  
 // 解析证书  
 cert, err := x509.ParseCertificate(block.Bytes)  
 if err != nil {  
 log.Fatalf("无法解析证书：%v", err)  
 }  
  
 // 打印证书信息  
 fmt.Printf("证书主题：%s\n", cert.Subject)  
 fmt.Printf("证书颁发者：%s\n", cert.Issuer)  
 fmt.Printf("证书有效期开始时间：%s\n", cert.NotBefore)  
 fmt.Printf("证书有效期结束时间：%s\n", cert.NotAfter)  
 // 打印其他证书信息...  
}