package main

import (  
    "fmt"  
    "io/ioutil"  
    "log"  
    "net/http"  
    "crypto/timestamp" 
    "crypto/x509"
    "encoding/pem"
    "time"
    "math/big"
    "crypto"
    "encoding/asn1"
    //"bytes"
)
func main() {  
    fmt.Println("启动成功")
    http.HandleFunc("/timestamp", handleTimestampRequest)  
    err := http.ListenAndServe(":8080", nil)  
    if err != nil {  
        log.Fatal("Server error: ", err)  
    }  

}

func handleTimestampRequest(w http.ResponseWriter, r *http.Request) {  
    // 读取请求体  
    reqbody, err := ioutil.ReadAll(r.Body)  
    if err != nil {  
        http.Error(w, "Failed to read request body", http.StatusBadRequest)  
        return  
    }  
    // 解析ASN.1数据  
    parsedRequest, err := timestamp.ParseRequest(reqbody)
    if err != nil {
        panic(err)
        fmt.Println("%x\n", parsedRequest.HashedMessage)
    }
    
// 读取证书和私钥文件
//SHA1

    TSAsha1certPEM, err := ioutil.ReadFile("C:\\Users\\28299\\Desktop\\MODPKICA\\GOcert\\TMPX\\PKI\\TIMSTAMP\\sha1.crt")
    if err != nil {
        fmt.Println("TSA签名证书加载失败！") 
        return
    }
    TSAsha1keyPEM, err := ioutil.ReadFile("C:\\Users\\28299\\Desktop\\MODPKICA\\GOcert\\TMPX\\PKI\\TIMSTAMP\\sha1.key")
    if err != nil {
        fmt.Println("TSA签名证书私钥加载失败！")   
        return
    }

    // 解码 PEM 格式的证书和私钥
    TSASHA1CRTblock, _ := pem.Decode(TSAsha1certPEM)
    if TSASHA1CRTblock == nil {
        http.Error(w, "Error decoding certificate PEM", http.StatusInternalServerError)
        return
    }
    TSASHA1cert, err := x509.ParseCertificate(TSASHA1CRTblock.Bytes)
    if err != nil {
        http.Error(w, "Error parsing certificate", http.StatusInternalServerError)
        return
    }
    TSASHA1KEYblock,_:= pem.Decode(TSAsha1keyPEM)
    if TSASHA1KEYblock == nil {
        http.Error(w, "Error decoding private key PEM", http.StatusInternalServerError)
        return
    }
    TSASHA1privateKey, err := x509.ParsePKCS1PrivateKey(TSASHA1KEYblock.Bytes)
    if err != nil {
        http.Error(w, "Error parsing private key", http.StatusInternalServerError)
        return
    }




//SHA256
    TSAsha256certPEM, err := ioutil.ReadFile("C:\\Users\\28299\\Desktop\\MODPKICA\\GOcert\\TMPX\\PKI\\TIMSTAMP\\sha256.crt")
    if err != nil {
        fmt.Println("TSA签名证书加载失败！") 
        return
    }
    TSAsha256keyPEM, err := ioutil.ReadFile("C:\\Users\\28299\\Desktop\\MODPKICA\\GOcert\\TMPX\\PKI\\TIMSTAMP\\sha256.key")
    if err != nil {
        fmt.Println("TSA签名证书私钥加载失败！")   
        return
    }

    // 解码 PEM 格式的证书和私钥
    TSASHA256CRTblock, _ := pem.Decode(TSAsha256certPEM)
    if TSASHA256CRTblock == nil {
        http.Error(w, "Error decoding certificate PEM", http.StatusInternalServerError)
        return
    }
    TSASHA256cert, err := x509.ParseCertificate(TSASHA256CRTblock.Bytes)
    if err != nil {
        http.Error(w, "Error parsing certificate", http.StatusInternalServerError)
        return
    }
    TSASHA256KEYblock,_:= pem.Decode(TSAsha256keyPEM)
    if TSASHA256KEYblock == nil {
        http.Error(w, "Error decoding private key PEM", http.StatusInternalServerError)
        return
    }
    TSASHA256privateKey, err := x509.ParsePKCS1PrivateKey(TSASHA256KEYblock.Bytes)
    if err != nil {
        http.Error(w, "Error parsing private key", http.StatusInternalServerError)
        return
    }
     
    ROOTcertPEM, err := ioutil.ReadFile("C:\\Users\\28299\\Desktop\\MODPKICA\\GOcert\\TMPX\\PKI\\ROOT\\root.crt")
    if err != nil {
        fmt.Println("ROOT签名证书加载失败！") 
        return
    }

    ROOTCRTblock, _ := pem.Decode(ROOTcertPEM)
    if ROOTCRTblock == nil {
        http.Error(w, "Error decoding certificate PEM", http.StatusInternalServerError)
        return
    }
    ROOTcert, err := x509.ParseCertificate(ROOTCRTblock.Bytes)
    if err != nil {
        http.Error(w, "Error parsing certificate", http.StatusInternalServerError)
        return
    }
    
    ioutil.WriteFile("rfc.req", reqbody, 0644) // 0644 是文件权限

    var response timestamp.Timestamp
    resthistime:=time.Now()
    Duration,_:=time.ParseDuration("1s")
    //response.RawToken=encodedToken + signature
    response.HashedMessage=parsedRequest.HashedMessage
    response.Time=resthistime
    response.HashAlgorithm=parsedRequest.HashAlgorithm
    response.Accuracy=Duration 
    response.Nonce=parsedRequest.Nonce
    response.Ordering=true
    response.Qualified=true
//1.2.840.113549.1.9.16.2.12  asn1.ObjectIdentifier{2,23,140,1,3} {2,4,5,6}    crypto.SHA256 parsedRequest.TSAPolicyOID
    response.Policy=asn1.ObjectIdentifier{2,23,140,1,3}
    response.SerialNumber=big.NewInt(time.Now().Unix())
    response.AddTSACertificate=parsedRequest.Certificates
    var certs []*x509.Certificate
    var timestampa []byte

    if(parsedRequest.HashAlgorithm==crypto.SHA1){
        
        certs = append(certs, ROOTcert) 
        certs = append(certs,TSASHA1cert)
        response.Certificates=certs 
        timestampa, err = response.CreateResponseWithOpts(TSASHA1cert,TSASHA1privateKey,parsedRequest.HashAlgorithm)  
        if err != nil {  
            http.Error(w, "Failed to generate timestamp: "+err.Error(), http.StatusInternalServerError)  
            return  
        } 
    }else{     
        certs = append(certs, ROOTcert) 
        certs = append(certs, TSASHA256cert)
        response.Certificates=certs 
        timestampa, err = response.CreateResponseWithOpts(TSASHA256cert,TSASHA256privateKey,parsedRequest.HashAlgorithm)  
        if err != nil {  
            http.Error(w, "Failed to generate timestamp: "+err.Error(), http.StatusInternalServerError)  
            return  
        } 
    }
    _,err=timestamp.ParseResponse(timestampa)
    if err != nil {
        fmt.Println("解析出错",err)
        return 
    }
    if parsedRequest.Nonce == nil {
        fmt.Println("RFC3161文档签名",parsedRequest.HashAlgorithm,parsedRequest.HashedMessage)
    
    }else{
        fmt.Println("RFC3161文档签名",parsedRequest.HashAlgorithm,parsedRequest.HashedMessage,"nonce",parsedRequest.Nonce)  
    }
    ioutil.WriteFile("rfc.res", timestampa, 0644) // 0644 是文件权限
    w.Header().Set("Content-Type", "application/timestamp-reply")  
    w.Write(timestampa)  
      
}