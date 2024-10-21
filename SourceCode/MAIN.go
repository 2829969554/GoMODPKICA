package main
//go mod init golang.org/x/crypto/ocsp
//go mod go mod tidy
import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"log" 
	"io" 
	"strconv"
	"bufio"
	"io/ioutil"
	"crypto/x509"
	//"crypto/x509/pkix"
	"encoding/pem"
	"time"
	"encoding/asn1"
	"encoding/hex"
	"crypto/sha1" 
	"os/exec"
	//"golang.org/x/crypto/ocsp"
	"crypto/ocsp"  //如果提示没有此包就需要手动复制Go包，详情请查看ReadMe.txt
	"crypto/rsa"
	"crypto/ecdsa"
	"encoding/base64"  
	//"go.mozilla.org/pkcs7" 
	"crypto/x509/pkcs7"//如果提示没有此包就需要手动复制Go包，详情请查看ReadMe.txt
	"bytes"
	"math/big"
    "crypto"
    "crypto/timestamp"   
)


//*************主线程 main 入口******************************
var GOBALMODTC string
func main() {

 ex, err := os.Executable()  
 if err != nil {  
 panic(err)  
 }  
//当前执行目录
MODTC:= filepath.Dir(ex) 
GOBALMODTC= MODTC
//所有证书记录表
MODPKI_certsfile:=MODTC+"\\PKI\\CERTS.txt"
//颁发者证书
MODPKI_ROOTfile:=MODTC+"\\PKI\\ROOT\\root.crt"
//生成吊销列表工具
MODPKI_ROOTGETCRLEXE:=MODTC+"\\rootGETcrl.exe"
//OCSP签名证书
MODPKI_OCSPfile:=MODTC+"\\PKI\\OCSP\\ocsp.crt"
MODPKI_OCSPfilekey:=MODTC+"\\PKI\\OCSP\\ocsp.key"
MODPKI_OCSPCAs:=MODTC+"\\PKI\\CA\\"   //{uid}.crt //{uid}.key
//时间戳服务
MODTIMSTAMPdir:=MODTC+"\\PKI\\TIMSTAMP\\"   //时间戳服务根目录
MODTIMSTAMPlogdir:=MODTIMSTAMPdir+"\\log\\" //时间戳req进 rsa出log日志目录
TSACERTsha1crt:=MODTIMSTAMPdir+"sha1.crt" 
TSACERTsha1key:=MODTIMSTAMPdir+"sha1.key"
TSACERTsha256crt:=MODTIMSTAMPdir+"sha256.crt"
TSACERTsha256key:=MODTIMSTAMPdir+"sha256.key"
//参数配置文件
MODCONFIG:=MODTC+"\\PKI\\CONFIG.txt"
//默认端口，具体以配置文件为准
MODWEBPORT:="80"
//公开访问目录
MODWebPublic:=MODTC+"\\PKI\\WebPublic"



//*************主线程 main 代码止 下面是WEB订阅函数******************************
// 启动时刷新CRL吊销列表  
cmd := exec.Command(MODPKI_ROOTGETCRLEXE,)  				  
// 运行命令并等待它完成  
cmd.CombinedOutput() 

//*********************************************************************************
//HTTP /OCSP在线证书状态协议监听函数

http.HandleFunc("/OCSP", func(w http.ResponseWriter, r *http.Request) {
if(r.Method!="POST"){
	fmt.Fprint(w,"/OCSP:在线证书状态协议查询接口：仅支持POST方式访问")
	return
}

//REQ为OCSP请求的ANS.1编码
REQ,err:=ioutil.ReadAll(r.Body)  
if err != nil {
	fmt.Println("OCSP:ERROR ioutil.read")
	return 
}
//ocspNonceOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2} 
last18Bytes := REQ[len(REQ) -18:]
var ocspNonce []byte
if(last18Bytes[0]==0x04 && last18Bytes[1]==0x10){
	ocspNonce=REQ[len(REQ) -16:]
}

  
 err = ioutil.WriteFile(MODTC+"\\PKI\\OCSP\\ocsp.req", REQ, 0644) // 将数据写入文件  
 if err != nil {  
 fmt.Println("写入文件时发生错误:", err)  
 return  
 }   


//res ans.1解码后的数据
res,err:=ocsp.ParseRequest(REQ)
if err != nil {
	fmt.Println("OCSP:ERROR JIE XI")
	return 
}


 // 打开证书状态列表 CERTS.txt 
 file, err := os.Open(MODPKI_certsfile)  
 if err != nil {  
 fmt.Println("无法打开文件:", err)  
 return  
 }  
 defer file.Close()  
  
 // 创建一个Scanner来读取文件内容  
 reader := bufio.NewReader(file)  
 Cstatus:="N"
 Cponse:=0
 Ctime := time.Now()
 Cbfcid:=""
    // 循环读取每一行  
    for{  
        line, err := reader.ReadString('\n')  
        if err != nil {  
            break 
        } 
        if(line[0]=='#'){
            continue
        }
         // 使用空格分隔每行文本  
         fields := strings.Split(line," ")  
         // 输出分隔后的结果  
         //fmt.Println(fields[0],fields[2],fields[3])
         if(fields[0]==res.SerialNumber.Text(16)){
         	//状态码V：正常  R：吊销   N：未知
         	Cstatus=fields[2]
         	Cbfcid=rftrn(fields[5])
             num2, err2 := strconv.Atoi(fields[3])  
             if err2 != nil {  
             fmt.Println("转换失败:", err2)  
             } 

             //吊销原因或者状态原因编号0-9
             Cponse=num2

             // 定义一个日期时间字符串  
             dateTimeStr := rftrn(fields[4])
              
             // 使用time包中的Parse函数将字符串解析为time.Time类型  
             layout := "2006/01/02-15:04:05"
             parsedTime, err := time.Parse(layout, dateTimeStr)  
             if err != nil {  
                 fmt.Println("解析日期时间失败:", err)  
                 return  
             }
             //签发时间或者注销时间
             Ctime =parsedTime
         	break
         } 
 
    } 
CEstatus:=2
    if(Cstatus=="N"){
    	if(len(ocspNonce)==16){
			log.Println("OCSP:未知证书,序列号",res.SerialNumber.Text(16),"Nonce",hex.EncodeToString(ocspNonce)) 
		}else{
			log.Println("OCSP:未知证书,序列号",res.SerialNumber.Text(16))
		}
    	
    	CEstatus=2
    }
    if(Cstatus=="V"){
    	if(len(ocspNonce)==16){
			log.Println("OCSP:证书正常,序列号",res.SerialNumber.Text(16),"Nonce",hex.EncodeToString(ocspNonce)) 
		}else{
			log.Println("OCSP:证书正常,序列号",res.SerialNumber.Text(16))
		}
    	CEstatus=0
    }
    if(Cstatus=="R"){
    	if(len(ocspNonce)==16){
			log.Println("OCSP:证书已吊销,序列号",res.SerialNumber.Text(16),"Nonce",hex.EncodeToString(ocspNonce)) 
		}else{
			log.Println("OCSP:证书已吊销,序列号",res.SerialNumber.Text(16))
		}
    	CEstatus=1
    }

/*
suijiNonce:=pkix.Extension{
        Id:       asn1.ObjectIdentifier{1,3,6,1,5,5,7,48,1,2},
        Critical: false,
        Value:    last18Bytes,//ocspNonce,
}
fmt.Print(suijiNonce)
*/

	MODPKI_OCSPfile=MODPKI_OCSPCAs+Cbfcid+".crt"
	MODPKI_OCSPfilekey=MODPKI_OCSPCAs+Cbfcid+".key"

	if _, err2 := os.Stat(MODPKI_OCSPfile); err2 != nil { 
		MODPKI_OCSPfile=MODTC+"\\PKI\\ROOT\\root.crt"
		MODPKI_OCSPfilekey=MODTC+"\\PKI\\ROOT\\root.key"
	}

	// 读取现有OCSP的证书和私钥文件
	ocspcertBytes, err := ioutil.ReadFile(MODPKI_OCSPfile)
	if err != nil {
		fmt.Println("Error reading OCSP certificate:", err)
		return
	}

	ocspkeyBytes, err := ioutil.ReadFile(MODPKI_OCSPfilekey)
	if err != nil {
		fmt.Println("Error reading OCSP key:", err)
		return
	}

	// 解析证书和私钥
	ocspcertBlock, _ := pem.Decode(ocspcertBytes)
	ocspcert, err := x509.ParseCertificate(ocspcertBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing  OCSP certificate:", err)
		return
	}

	ocspkeyBlock, _ := pem.Decode(ocspkeyBytes)

	var ECCocspprivKey *ecdsa.PrivateKey
	var RSAocspprivKey *rsa.PrivateKey
	Keytype := "RSA"

	if(ocspkeyBlock.Type == "EC PRIVATE KEY"){
		//ECDSA类型私钥
		Keytype = "ECC"
		ocspprivKey, err := x509.ParseECPrivateKey(ocspkeyBlock.Bytes)
		ECCocspprivKey = ocspprivKey
		if err != nil {
			fmt.Println("ECC Error parsing OCSP private key:", err)
			return
		}
	}
	if(ocspkeyBlock.Type == "RSA PRIVATE KEY"){
		//RSA类型私钥
		Keytype = "RSA"
		ocspprivKey, err := x509.ParsePKCS1PrivateKey(ocspkeyBlock.Bytes)
		RSAocspprivKey = ocspprivKey
		if err != nil {
			fmt.Println("RSA Error parsing OCSP private key:", err)
			return
		}
	}	
	if(ocspkeyBlock.Type == "SM2 PRIVATE KEY"){
		//RSA类型私钥
		Keytype = "SM2"
		fmt.Println("ERROR：暂不支持国密OCSP协议！")
		if err != nil {
			fmt.Println("SM2 Error parsing OCSP private key:", err)
			return
		}
	}	
	



	MODPKI_ROOTfile=MODPKI_OCSPfile
	// 读取现有颁发者的证书
	ROOTcertBytes, err := ioutil.ReadFile(MODPKI_ROOTfile)
	if err != nil {
		fmt.Println("Error reading ROOT certificate:", err)
		return
	}
	// 解析ROOT证书
	rootBlock, _ := pem.Decode(ROOTcertBytes)
	rootcert, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing  ROOT certificate:", err)
		return
	}



// 创建OCSP响应对象模板  
 ocspResp := ocsp.Response{  
	 RevocationReason:Cponse,
	 SignatureAlgorithm:x509.SHA256WithRSA,
	 ProducedAt:time.Now().UTC(),
	 ThisUpdate:time.Now().UTC().Add(-10 * time.Minute),
	 NextUpdate:time.Now().UTC().Add(10 * time.Minute),
	 RevokedAt:Ctime.UTC(),
	 //IssuerHash:0,
	 //Extensions:[]pkix.Extension{suijiNonce},
	 //ExtraExtensions:[]pkix.Extension{suijiNonce},
	 Certificate:ocspcert,
	 Status:  CEstatus,   //0,1,2 {Good, Revoked, Unknown}这里假设状态为"good"，你可以根据实际情况修改这个值。其他可选状态包括：ocsp.Revoked、ocsp.Unknown。  
	 SerialNumber: res.SerialNumber, // 设置响应的序列号，与证书的序列号相同。如果OCSP请求中指定了序列号，则应该与证书的序列号匹配。  
	 
 } 



 //给OCSP响应对象模板签名转ANS.1数据[]byte（使用证书和私钥作为签名者）
var ocspRespBytes []byte
if(Keytype == "RSA"){
	ocspResp.SignatureAlgorithm=x509.SHA1WithRSA
 	ocspRespBytestmp, err := ocsp.CreateResponse(rootcert,ocspcert , ocspResp, RSAocspprivKey) // 创建OCSP响应的字节数据，返回响应的字节数据和错误（如果有的话）  
	 if err != nil {  
	 fmt.Println(
	 	"Error creating OCSP response:", err)  
	 return  
	 } 
	 ocspRespBytes = ocspRespBytestmp
}
if(Keytype == "ECC"){
	ocspResp.SignatureAlgorithm=x509.ECDSAWithSHA1
 	ocspRespBytestmp, err := ocsp.CreateResponse(rootcert,ocspcert , ocspResp, ECCocspprivKey) // 创建OCSP响应的字节数据，返回响应的字节数据和错误（如果有的话）  
	 if err != nil {  
	 fmt.Println(
	 	"Error creating OCSP response:", err)  
	 return  
	 } 
	 ocspRespBytes = ocspRespBytestmp
}
if(Keytype == "SM2"){
		fmt.Println("ERROR：暂不支持国密OCSP协议！")
		return 
}
	 w.Header().Set("Content-Type", "application/ocsp-response") 
	 w.Header().Set("Content-Length", strconv.FormatInt(int64(len(ocspRespBytes)), 10) ) 
	 //w.:用http响应将数据输出
  _, err = w.Write(ocspRespBytes)  
			 if err != nil {  
			 	http.Error(w, "Failed to write response", http.StatusInternalServerError)  
			 	return  
			 } 
 err = ioutil.WriteFile(MODTC+"\\PKI\\OCSP\\ocsp.res", ocspRespBytes, 0644)  
if err != nil {  
    fmt.Println("Error saving OCSP response:", err)  
    return  
} 
return


})


//***********************************************************


	//网站目录WebPublic 监听函数

	//监听网站目录/CRL 和 CRT
	
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		 filePath := r.URL.String() 
		 if(filePath=="/ocsp" || filePath=="/ocsp/"  || filePath=="/OCSP/"){
		 	 w.Header().Set("Location", "/OCSP")  
			 w.WriteHeader(http.StatusMovedPermanently)
			 return
		 }
		 //不带参数
		 if(filePath=="/"){
		 	fmt.Fprint(w,"欢迎访问 MOD PKI CA 基础服务页面。")  
		 	return
		 }
		 /* 更新太快了，暂时屏蔽改为main启动时刷新CRL一次
		 //判断左边是不是/CRL，如果是就刷新
		 if strings.HasPrefix(filePath, "/CRL") {  
		  	 // 创建一个*Cmd对象，表示要执行的命令  
			cmd := exec.Command(MODPKI_ROOTGETCRLEXE,)  				  
			// 运行命令并等待它完成  
			 cmd.CombinedOutput()  
		 }
		 */

		 //将请求URL/CRT/root.crt中的/转为\\
		 filePath = strings.Replace(filePath, "/", "\\\\", -1)  
		 filePath = MODWebPublic + filePath
		 // 使用os.Stat检查文件是否存在  文件存在则继续，不存在直接返回
		 if _, err2 := os.Stat(filePath); err2 == nil {  

			 // 设置响应头，指定文件类型和大小  
			 file, err3 := os.Open(filePath)  
			 if err3 != nil {  
			   log.Fatal(err3)  
			 }  
			 defer file.Close()  
			 // 将文件内容读取到字节切片中  
			 fileBytes, err6 := io.ReadAll(file)  
			 if err6 != nil {  
			 	http.Error(w, "Failed to read file", http.StatusInternalServerError)  
			 return  
			 }   

			 fileInfo, err4 := file.Stat()  
			 if err4 != nil {  
			 	log.Fatal(err4)  
			 }  
			 fileSize := strconv.FormatInt(int64(fileInfo.Size()), 10)   
			 wenjianhouzhui:=file.Name()
			 wenjianhouzhui=wenjianhouzhui[len(wenjianhouzhui)-3:]
			 w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filePath))  
			w.Header().Set("Content-Type", "application/octet-stream")
			if(wenjianhouzhui=="crl"){
				w.Header().Set("Content-Type", "application/pkix-crl")
				log.Println("授权信息访问 CRL分发点 URL", r.URL)
			}
			if(wenjianhouzhui=="crt"){
				w.Header().Set("Content-Type", "application/pkix-cert")
				log.Println("授权信息访问 证书颁发机构颁发者 URL", r.URL)
			}
			

			 w.Header().Set("Content-Length", fileSize)  

			  
			  _, err = w.Write(fileBytes)  
			 if err != nil {  
			 	http.Error(w, "Failed to write response", http.StatusInternalServerError)  
			 	return  
			 } 

		 	
		 } else if os.IsNotExist(err2) {  
		 	fmt.Fprint(w,"404：访问地址不存在")   
		 } else {  
		 	fmt.Println("unknow：未知错误或权限不足。", err2)  
		 }  
		

return
	})


//********时间戳服务端代码******************************


//Timestamp时间戳服务器 SHA256签名
http.HandleFunc("/timestamp", func(w http.ResponseWriter, r *http.Request) {
	//定义时间戳服务端需要的全局变量

	if r.Method != http.MethodPost {
		w.Write([]byte("欢迎访问MODPKICA系统可信时间戳服务，此接口仅允许POST方式提交数据"))
		return
	}
	reqtype:=r.Header.Get("Content-Type")
	if(reqtype == "application/timestamp-query"){
		handleTimestampRequest(w,r)
		return
	}


	// 读取请求体中的数据
	data,_:= ioutil.ReadAll(r.Body)

	// 读取证书和私钥文件
	TSAcertPEM, err := ioutil.ReadFile(TSACERTsha256crt)
	if err != nil {
		fmt.Println("TSA签名证书加载失败！")	
		return
	}

	TSAkeyPEM, err := ioutil.ReadFile(TSACERTsha256key)
	if err != nil {
		fmt.Println("TSA签名证书私钥加载失败！")	
		return
	}

	// 解码 PEM 格式的证书和私钥
	TSACRTblock, _ := pem.Decode(TSAcertPEM)
	if TSACRTblock == nil {
		http.Error(w, "无法加载TSA专用签名证书", http.StatusInternalServerError)
		return
	}
	TSAcert, err := x509.ParseCertificate(TSACRTblock.Bytes)
	if err != nil {
		http.Error(w, "无法解析TSA专用签名证书", http.StatusInternalServerError)
		return
	}
	TSAKEYblock,_:= pem.Decode(TSAkeyPEM)
	if TSAKEYblock == nil {
		http.Error(w, "无法加载TSA私钥", http.StatusInternalServerError)
		return
	}
	TSAprivateKey, err := x509.ParsePKCS1PrivateKey(TSAKEYblock.Bytes)
	if err != nil {
		http.Error(w, "无法解析TSA私钥", http.StatusInternalServerError)
		return
	}

    
	  // 解码Base64字符串  
	  data=data[:len(data)-1]
	  decodedBytes, err := base64.StdEncoding.DecodeString(string(data))  
	 	if err != nil {  
		 	fmt.Println("解码失败:当前请求不是Authenticode签名!") 
		 	 
		 	return  
		}
		
		reqbody:=data  //时间戳请求原始数据
		data=decodedBytes  //Authenticode签名
     parts := bytes.Split(data, []byte{0x04, 0x82})  

    if(len(parts)==2){
    	data=data[len(data)-(len(parts[1])-2):]
    }else{
    	fmt.Println("SHA 256 Authenticode报错找不到关键0x04 0x82")
    	return
    }
    

	// 生成 Authenticode 签名 digitype 1 : sha1  2:sha256   3:sha384  4:sha512
	signature, err := SignAndDetach(data, TSAcert, TSAprivateKey,2)
	if err != nil {
		http.Error(w, "签名过程出错", http.StatusInternalServerError)
		fmt.Println("签名过程出错",err)
		return
	}
	datasha1:=sha1.Sum(data)
	datasha1hash:=hex.EncodeToString(datasha1[:]) 
	log.Println("时间戳签名 Authenticode  SHA256 ",datasha1hash)
	ioutil.WriteFile(MODTIMSTAMPlogdir+datasha1hash+".req", reqbody, 0644) // 0644 是文件权限

	ioutil.WriteFile(MODTIMSTAMPlogdir+datasha1hash+".res", signature, 0644)
	//w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Type", "application/timestamp-reply") 
	w.Header().Set("Content-Length",  strconv.Itoa(len(signature))) 
	w.Write(signature)
})


//***********************************************************************

//Timestamp时间戳服务器 SHA1签名
http.HandleFunc("/timestamp/sha1", func(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.Write([]byte("欢迎访问MODPKICA系统可信时间戳服务，此接口仅允许POST方式提交数据"))
		return
	}
	reqtype:=r.Header.Get("Content-Type")
	if(reqtype == "application/timestamp-query"){
		handleTimestampRequest(w,r)
		return
	}

	// 读取请求体中的数据
	data,_:= ioutil.ReadAll(r.Body)


	// 读取证书和私钥文件
	TSAcertPEM, err := ioutil.ReadFile(TSACERTsha1crt)
	if err != nil {
		fmt.Println("TSA签名证书加载失败！")	
		return
	}

	TSAkeyPEM, err := ioutil.ReadFile(TSACERTsha1key)
	if err != nil {
		fmt.Println("TSA签名证书私钥加载失败！")	
		return
	}

	// 解码 PEM 格式的证书和私钥
	TSACRTblock, _ := pem.Decode(TSAcertPEM)
	if TSACRTblock == nil {
		http.Error(w, "无法加载TSA专用签名证书", http.StatusInternalServerError)
		return
	}
	TSAcert, err := x509.ParseCertificate(TSACRTblock.Bytes)
	if err != nil {
		http.Error(w, "无法解析TSA专用签名证书", http.StatusInternalServerError)
		return
	}
	TSAKEYblock,_:= pem.Decode(TSAkeyPEM)
	if TSAKEYblock == nil {
		http.Error(w, "无法加载TSA私钥", http.StatusInternalServerError)
		return
	}
	TSAprivateKey, err := x509.ParsePKCS1PrivateKey(TSAKEYblock.Bytes)
	if err != nil {
		http.Error(w, "无法解析TSA私钥", http.StatusInternalServerError)
		return
	}

    
	  // 解码Base64字符串  
	  data=data[:len(data)-1]
	  decodedBytes, err := base64.StdEncoding.DecodeString(string(data))  
	 	if err != nil {  
		 	fmt.Println("解码失败:当前请求不是Authenticode签名!")  
		 	return  
		}
		reqbody:=data  //时间戳请求原始数据
		data=decodedBytes  //Authenticode签名
     parts := bytes.Split(data, []byte{0x04, 0x82})  

    if(len(parts)==2){
    	data=data[len(data)-(len(parts[1])-2):]
    }else{
    	fmt.Println("SHA 256 Authenticode报错找不到关键0x04 0x82")
    	return
    }

	// 生成 Authenticode 签名 digitype 1 : sha1  2:sha256   3:sha384  4:sha512
	signature, err := SignAndDetach(data, TSAcert, TSAprivateKey,1)
	if err != nil {
		http.Error(w, "签名过程出错", http.StatusInternalServerError)
		fmt.Println("签名过程出错",err)
		return
	}
	datasha1:=sha1.Sum(data)
	datasha1hash:=hex.EncodeToString(datasha1[:]) 
	log.Println("时间戳签名 Authenticode  SHA1 ",datasha1hash)
	ioutil.WriteFile(MODTIMSTAMPlogdir+datasha1hash+".req", reqbody, 0644) // 0644 是文件权限

	ioutil.WriteFile(MODTIMSTAMPlogdir+datasha1hash+".res", signature, 0644)
	//w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Type", "application/timestamp-reply") 
	w.Header().Set("Content-Length",  strconv.Itoa(len(signature))) 
	w.Write(signature)
})



//********主线程 Main 函数 衔接 上方为视图订阅函数************


// 打开文件MODPKICA配置文件
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
        if(parts[0]=="WEBPORT"){
            MODWEBPORT=rftrn(parts[1])
            break
        }
    } 


	fmt.Println("MOD PKI CA Server is running on http://localhost:"+MODWEBPORT)
	fmt.Println("MOD PKI CA 服务端启动: http://localhost:"+MODWEBPORT)
	fmt.Println("MOD PKI CA 网页管理端 服务启动: http://localhost:"+MODWEBPORT+"/ADMIN")
	fmt.Println("MOD PKI CA 颁发者授权信息 服务启动: http://localhost:"+MODWEBPORT+"/CRT")
	fmt.Println("MOD PKI CA 颁发者吊销列表 服务启动: http://localhost:"+MODWEBPORT+"/CRL")
	fmt.Println("MOD PKI CA OCSP服务启动: http://localhost:"+MODWEBPORT+"/OCSP")
	fmt.Println("MOD PKI CA 微软Authenticode时间戳SHA1     服务启动: http://localhost:"+MODWEBPORT+"/timestamp/sha1")
	fmt.Println("MOD PKI CA 微软Authenticode时间戳SHA256   服务启动: http://localhost:"+MODWEBPORT+"/timestamp")
	fmt.Println("MOD PKI CA RFC3161文档(PDF)签名专用时间戳(SHA1&SHA256自适应)  服务启动: http://localhost:"+MODWEBPORT+"/rfc3161")
	
	
	fmt.Println("MOD PKI CA 监听端口  :"+MODWEBPORT)
	fmt.Println("如需修改配置请编辑./PKI/CONFIG.txt文件")
	fmt.Println("本程序作者：@魔帝本尊  QQ：2829969554")
	fmt.Println("MOD PKI CA SERVER支持x.509 证书管理、CRL吊销列表、时间戳服务器、OCSP在线状态协议、自动化签发。")
	fmt.Println("本系统仅供学习 x.509 ASN.1编码使用。作者不承担任何由此产生的一切问题。")
    http.HandleFunc("/rfc3161", handleTimestampRequest) 
	err1 := http.ListenAndServe(":"+MODWEBPORT, nil)
	if err1 != nil {
		fmt.Println("错误 服务端启动失败:", err1)
	}

}

//********主线程 Main函数 结束**************************************






//****************自定义函数声明区***********************
 
 //去掉结尾的\n
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


//Authenticode签名函数
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

//****************************************************************



//RFC3161 TIMESTAMP
func handleTimestampRequest(w http.ResponseWriter, r *http.Request) { 

MODPKI_ROOTfile:=GOBALMODTC+"\\PKI\\ROOT\\root.crt"
MODTIMSTAMPdir:=GOBALMODTC+"\\PKI\\TIMSTAMP\\" 
MODTIMSTAMPlogdir:=MODTIMSTAMPdir+"\\log\\" //时间戳req进 rsa出log日志目录
TSACERTsha1crt:=MODTIMSTAMPdir+"sha1.crt" 
TSACERTsha1key:=MODTIMSTAMPdir+"sha1.key"
TSACERTsha256crt:=MODTIMSTAMPdir+"sha256.crt"
TSACERTsha256key:=MODTIMSTAMPdir+"sha256.key"
    // 读取请求体  
    reqbody, err := ioutil.ReadAll(r.Body)  
    if err != nil {  
        http.Error(w, "Failed to read request body", http.StatusBadRequest)  
        return  
    }  
    // 解析ASN.1数据  
    parsedRequest, err := timestamp.ParseRequest(reqbody)
    if err != nil {
        fmt.Println("解析失败，当前请求不是RFC3161文档签名")
        return
    }
    
// 读取证书和私钥文件
//SHA1

    TSAsha1certPEM, err := ioutil.ReadFile(TSACERTsha1crt)
    if err != nil {
        fmt.Println("TSA签名证书加载失败！") 
        return
    }
    TSAsha1keyPEM, err := ioutil.ReadFile(TSACERTsha1key)
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
    TSAsha256certPEM, err := ioutil.ReadFile(TSACERTsha256crt)
    if err != nil {
        fmt.Println("TSA签名证书加载失败！") 
        return
    }
    TSAsha256keyPEM, err := ioutil.ReadFile(TSACERTsha256key)
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
     
    ROOTcertPEM, err := ioutil.ReadFile(MODPKI_ROOTfile)
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
    
   
    var response timestamp.Timestamp
    resthistime:=time.Now()
    Duration,_:=time.ParseDuration("1s")
    //response.RawToken=encodedToken + signature
    response.HashedMessage=parsedRequest.HashedMessage
    response.Time=resthistime.UTC()
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
    datasha1:=sha1.Sum(parsedRequest.HashedMessage)
	datasha1hash:=hex.EncodeToString(datasha1[:]) 
    if parsedRequest.Nonce == nil {
        log.Println("时间戳签名 RFC3161文档签名",parsedRequest.HashAlgorithm,datasha1hash)
    
    }else{
        log.Println("时间戳签名 RFC3161文档签名",parsedRequest.HashAlgorithm,datasha1hash,"nonce",parsedRequest.Nonce)  
    }
    ioutil.WriteFile(MODTIMSTAMPlogdir+"rfc3161"+datasha1hash+".req", reqbody, 0644) // 0644 是文件权限
    ioutil.WriteFile(MODTIMSTAMPlogdir+"rfc3161"+datasha1hash+".res", timestampa, 0644) // 0644 是文件权限
    w.Header().Set("Content-Type", "application/timestamp-reply")  
    w.Header().Set("Content-Length",  strconv.Itoa(len(timestampa))) 
    w.Write(timestampa)  
      
}