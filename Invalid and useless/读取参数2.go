package main  
  
import (  
 "crypto/x509"  
 "encoding/pem"  
 "fmt"  
 "io/ioutil"  
 "log"  
)  
  
func main() {  
 // 读取证书文件  
 certFile := "www.boc.cn.crt"  
 certPEM, err := ioutil.ReadFile(certFile)  
 if err != nil {  
 log.Fatal("Failed to read certificate file:", err)  
 }  
  
 // 解码证书PEM  
 block, _ := pem.Decode(certPEM)  
 if block == nil {  
 log.Fatal("Failed to decode PEM block")  
 }  
  
 // 解析证书  
 cert, err := x509.ParseCertificate(block.Bytes)  
 if err != nil {  
 log.Fatal("Failed to parse certificate:", err)  
 }  
  
 // 打印证书信息  
 fmt.Println(cert)/*
 fmt.Println("证书主题：", cert.Subject.CommonName)  
 fmt.Println("证书颁发者：", cert.Issuer.CommonName)  
 fmt.Println("证书有效期开始时间：", cert.NotBefore)  
 fmt.Println("证书有效期结束时间：", cert.NotAfter)  */
}