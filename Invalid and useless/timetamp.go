package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/asn1"
	"encoding/base64"  
	"io/ioutil"
	"net/http"
	"fmt"
	//"go.mozilla.org/pkcs7" 
	"crypto/x509/pkcs7"
	"bytes"
)

func main() {
	http.HandleFunc("/timstamp", handletimstampSignRequest)
	http.ListenAndServe(":8080", nil)
}
//Authenticode 签名
func handletimstampSignRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Write([]byte("欢迎访问MODPKICA系统可信时间戳服务，此接口仅允许POST方式提交数据"))
		return
	}


	// 读取请求体中的数据
	data,_:= ioutil.ReadAll(r.Body)


	// 读取证书和私钥文件
	TSAcertPEM, err := ioutil.ReadFile("C:\\git\\modpkica\\PKI\\ROOT\\root.crt")
	if err != nil {
		fmt.Println("TSA签名证书加载失败！")	
		return
	}

	TSAkeyPEM, err := ioutil.ReadFile("C:\\git\\modpkica\\PKI\\ROOT\\root.key")
	if err != nil {
		fmt.Println("TSA签名证书私钥加载失败！")	
		return
	}

	// 解码 PEM 格式的证书和私钥
	TSACRTblock, _ := pem.Decode(TSAcertPEM)
	if TSACRTblock == nil {
		http.Error(w, "Error decoding certificate PEM", http.StatusInternalServerError)
		return
	}
	TSAcert, err := x509.ParseCertificate(TSACRTblock.Bytes)
	if err != nil {
		http.Error(w, "Error parsing certificate", http.StatusInternalServerError)
		return
	}
	TSAKEYblock,_:= pem.Decode(TSAkeyPEM)
	if TSAKEYblock == nil {
		http.Error(w, "Error decoding private key PEM", http.StatusInternalServerError)
		return
	}
	TSAprivateKey, err := x509.ParsePKCS1PrivateKey(TSAKEYblock.Bytes)
	if err != nil {
		http.Error(w, "Error parsing private key", http.StatusInternalServerError)
		return
	}
	
	ioutil.WriteFile("C:\\Users\\28299\\Desktop\\my.req", data, 0644) // 0644 是文件权限
    
    
	  // 解码Base64字符串  
	  data=data[:len(data)-1]
	  decodedBytes, err := base64.StdEncoding.DecodeString(string(data))  
	 	if err != nil {  
		 	fmt.Println("解码失败:", err)  
		 	return  
		}
		//Authenticode
		data=decodedBytes

      //时间戳请求原始数据
      data=data[len(data)-512:]
	
	// 生成 Authenticode 签名 digitype 1 : sha1  2:sha256   3:sha384  4:sha512
	signature, err := SignAndDetach(data, TSAcert, TSAprivateKey,3)
	if err != nil {
		http.Error(w, "Error signing data", http.StatusInternalServerError)
		fmt.Println("签名过程出错",err)
		return
	}
	ioutil.WriteFile("C:\\Users\\28299\\Desktop\\myt.res", signature, 0644)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(signature)
}


//MOD变量第四个变量整数 digitype 1 : sha1  2:sha256   3:sha384  4:sha512
func SignAndDetach(content []byte, cert *x509.Certificate, privkey *rsa.PrivateKey,digitype int) (signed []byte, err error) {
	toBeSigned, err := pkcs7.NewSignedData(content)
	if err != nil {
		err = fmt.Errorf("Cannot initialize signed data: %s", err)
		return
	}
	//扩展信息 自定义目前防止的摘要
	mtdime:=[]pkcs7.Attribute{
		pkcs7.Attribute{
			Type:asn1.ObjectIdentifier{1,2,840,113549,1,7,1},
			Value:interface{}(content),
		},

	}

	if(digitype==1){
	   //sha1
	   toBeSigned.SetDigestAlgorithm(asn1.ObjectIdentifier{1,3,14,3,2,26})
	}
	if(digitype==2){
	   //sha256
	   toBeSigned.SetDigestAlgorithm(asn1.ObjectIdentifier{2,16,840,1,101,3,4,2,1})
	}
	if(digitype==3){
	   //sha384
	   toBeSigned.SetDigestAlgorithm(asn1.ObjectIdentifier{2,16,840,1,101,3,4,2,2})
	}
	if(digitype==4){
		//sha512
	   toBeSigned.SetDigestAlgorithm(asn1.ObjectIdentifier{2,16,840,1,101,3,4,2,3})
	}

	if err = toBeSigned.AddSigner(cert, privkey, pkcs7.SignerInfoConfig{ExtraSignedAttributes:mtdime }); err != nil {
		err = fmt.Errorf("Cannot add signer: %s", err)
		return
	}
	signed, err = toBeSigned.Finish()
	if err != nil {
		err = fmt.Errorf("Cannot finish signing data: %s", err)
		return
	}

	// Verify the signature
	pemder:=pem.EncodeToMemory(&pem.Block{Type: "PKCS7", Bytes: signed})
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		err = fmt.Errorf("Cannot parse our signed data: %s", err)
		return
	}

	p7.Content = content

	if bytes.Compare(content, p7.Content) != 0 {
		err = fmt.Errorf("Our content was not in the parsed data:\n\tExpected: %s\n\tActual: %s", content, p7.Content)
		return
	}
	if err = p7.Verify(); err != nil {
		err = fmt.Errorf("Cannot verify our signed data: %s", err)
		return
	}
	//输出PEM文本格式签名信息 但是不包括头部和尾部
	pemder=bytes.ReplaceAll(pemder, []byte("\n-----END PKCS7-----"), []byte("\r"))
	pemder=bytes.ReplaceAll(pemder, []byte("-----BEGIN PKCS7-----\n"), []byte(""))
	return pemder, nil
}
