package main
//go mod init golang.org/x/crypto/ocsp
//go mod go mod tidy
import (
	 "crypto/x509"
	 "encoding/pem"
	 "fmt"
	 "io/ioutil" 
	 "crypto/ocsp"
	 "time"
	 //"golang.org/x/crypto/ocsp"
)

func main() {
	// 读取现有的证书和私钥文件
	certBytes, err := ioutil.ReadFile("C:\\Users\\28299\\Desktop\\MODPKICA\\GOcert\\TMPX\\PKI\\ROOT\\root.crt")
	if err != nil {
		fmt.Println("Error reading certificate:", err)
		return
	}

	keyBytes, err := ioutil.ReadFile("C:\\Users\\28299\\Desktop\\MODPKICA\\GOcert\\TMPX\\PKI\\ROOT\\root.key")
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return
	}

	// 解析证书和私钥
	certBlock, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing certificate:", err)
		return
	}

	keyBlock, _ := pem.Decode(keyBytes)
	privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}

// 创建OCSP响应对象（使用证书和私钥作为签名者）  
 ocspResp := ocsp.Response{  
	 RevocationReason:5,
	 SignatureAlgorithm:x509.SHA256WithRSA,
	 ProducedAt:time.Now(),
	 ThisUpdate:time.Now(),
	 NextUpdate:time.Now().Add(10 * time.Minute),
	 RevokedAt:time.Now(),
	 IssuerHash:0,
	 //Certificate:cert,
	 Status:  ocsp.Good,   //0,1,2 {Good, Revoked, Unknown}这里假设状态为"good"，你可以根据实际情况修改这个值。其他可选状态包括：ocsp.Revoked、ocsp.Unknown。  
	 SerialNumber: cert.SerialNumber, // 设置响应的序列号，与证书的序列号相同。如果OCSP请求中指定了序列号，则应该与证书的序列号匹配。  
	 
 } 


 
 ocspRespBytes, err := ocsp.CreateResponse(cert,cert , ocspResp, privKey) // 创建OCSP响应的字节数据，返回响应的字节数据和错误（如果有的话）  
	 if err != nil {  
	 fmt.Println(
	 	"Error creating OCSP response:", err)  
	 return  
	 }  
 
 err = ioutil.WriteFile("C:\\Users\\28299\\Desktop\\MODPKICA\\GOcert\\TMPX\\PKI\\ROOT\\root.ocsp", ocspRespBytes, 0644)  
if err != nil {  
    fmt.Println("Error saving OCSP response:", err)  
    return  
}  
  
 fmt.Println("OCSP response saved successfully!")
 fmt.Println(ocspRespBytes)  



}

