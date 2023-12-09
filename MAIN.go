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
	"crypto/ocsp"
	"io/ioutil"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"time"
	"encoding/asn1"
	"encoding/hex"
	"os/exec"
	//"golang.org/x/crypto/ocsp"
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
//颁发者证书
MODPKI_ROOTfile:=MODTC+"\\PKI\\ROOT\\root.crt"
//生成吊销列表工具
MODPKI_ROOTGETCRLEXE:=MODTC+"\\rootGETcrl.exe"
//OCSP签名证书
MODPKI_OCSPfile:=MODTC+"\\PKI\\OCSP\\ocsp.crt"
MODPKI_OCSPfilekey:=MODTC+"\\PKI\\OCSP\\ocsp.key"

//公开访问目录
MODWebPublic:=MODTC+"\\PKI\\WebPublic"


	// 读取现有OCSP的证书和私钥文件
	certBytes, err := ioutil.ReadFile(MODPKI_OCSPfile)
	if err != nil {
		fmt.Println("Error reading OCSP certificate:", err)
		return
	}

	keyBytes, err := ioutil.ReadFile(MODPKI_OCSPfilekey)
	if err != nil {
		fmt.Println("Error reading OCSP key:", err)
		return
	}

	// 解析证书和私钥
	certBlock, _ := pem.Decode(certBytes)
	ocspcert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing  OCSP certificate:", err)
		return
	}

	keyBlock, _ := pem.Decode(keyBytes)
	ocspprivKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing OCSP private key:", err)
		return
	}

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


//res结构体数据参数
//fmt.Println(res.HashAlgorithm)
//fmt.Println(res.IssuerNameHash)
//fmt.Println(res.IssuerKeyHash)
//fmt.Println(res.SerialNumber)

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

suijiNonce:=pkix.Extension{
        Id:       asn1.ObjectIdentifier{1,3,6,1,5,5,7,48,1,2},
        Critical: false,
        Value:    last18Bytes,//ocspNonce,
}
// 创建OCSP响应对象模板  
 ocspResp := ocsp.Response{  
	 RevocationReason:Cponse,
	 SignatureAlgorithm:x509.SHA256WithRSA,
	 ProducedAt:time.Now(),
	 ThisUpdate:time.Now(),
	 NextUpdate:time.Now().Add(10 * time.Minute),
	 RevokedAt:Ctime,
	 IssuerHash:0,
	 Extensions:[]pkix.Extension{suijiNonce},
	 ExtraExtensions:[]pkix.Extension{suijiNonce},
	 Certificate:ocspcert,
	 Status:  CEstatus,   //0,1,2 {Good, Revoked, Unknown}这里假设状态为"good"，你可以根据实际情况修改这个值。其他可选状态包括：ocsp.Revoked、ocsp.Unknown。  
	 SerialNumber: res.SerialNumber, // 设置响应的序列号，与证书的序列号相同。如果OCSP请求中指定了序列号，则应该与证书的序列号匹配。  
	 
 } 


 //给OCSP响应对象模板签名转ANS.1数据[]byte（使用证书和私钥作为签名者）
 ocspRespBytes, err := ocsp.CreateResponse(rootcert,ocspcert , ocspResp, ocspprivKey) // 创建OCSP响应的字节数据，返回响应的字节数据和错误（如果有的话）  
	 if err != nil {  
	 fmt.Println(
	 	"Error creating OCSP response:", err)  
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
//*******************

})

	//网站目录WebPublic 监听函数

	//监听网站目录/CRL 和 CRT
	
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		 filePath := r.URL.String() 

		 //不带参数
		 if(filePath=="/"){
		 	fmt.Fprint(w,"欢迎访问 MOD PKI CA 基础服务页面。")  
		 	return
		 }
		 //判断左边是不是/CRL，如果是就刷新
		 if strings.HasPrefix(filePath, "/CRL") {  
		  	 // 创建一个*Cmd对象，表示要执行的命令  
			cmd := exec.Command(MODPKI_ROOTGETCRLEXE,)  				  
			// 运行命令并等待它完成  
			 cmd.CombinedOutput()  
		 }

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
			 fileType := http.DetectContentType([]byte(file.Name()))  
			 log.Println("URL", r.URL) 
			 log.Println("File type:", fileType)  
			 log.Println("File size:", fileSize)  
			 log.Println("File",file.Name()) 
			 w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filePath))  
			 w.Header().Set("Content-Type", fileType)  
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



//主线程Main函数

//参数配置文件
MODCONFIG:=MODTC+"\\PKI\\CONFIG.txt"
//默认端口，具体以配置文件为准

MODWEBPORT:="80"
// 打开文件  
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
	fmt.Println("MOD PKI CA 监听端口  :"+MODWEBPORT)
	fmt.Println("如需修改配置请编辑./PKI/CONFIG.txt文件")
	fmt.Println("本程序作者：@魔帝本尊  QQ：2829969554")
	fmt.Println("MOD PKI CA SERVER支持x.509 证书管理、CRL吊销列表、OCSP在线状态协议、自动化签发。")
	fmt.Println("本系统仅供学习 x.509 ASN.1编码使用。作者不承担任何由此产生的一切问题。")
	err1 := http.ListenAndServe(":"+MODWEBPORT, nil)
	if err1 != nil {
		fmt.Println("Error starting server:", err1)
	}
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