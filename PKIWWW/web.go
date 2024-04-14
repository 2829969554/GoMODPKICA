package main  
//go build web.go api.go   使用该命令编译  api.go中是公共函数
import (  
 "crypto/tls" 
 "crypto/x509"  
 "fmt"  
 "net/http"
 "net/url" 
 "io/ioutil" 
 "os" 
 "strings" 
 "encoding/json"
 "strconv"
 "bytes"
 "time"
)  
  
func main() { 
 // 创建HTTP服务器  
 httpServer := &http.Server{  
 Addr:      ":8080", // 监听的端口号  
 Handler:   http.HandlerFunc(handleRequest), // 处理请求的函数  
 }  
httpscert,_:=tls.LoadX509KeyPair("6617e046.crt", "6617e046.key")
cacerts,_:= ioutil.ReadFile("ca.crt") 
cacertPool := x509.NewCertPool()  
cacertPool.AppendCertsFromPEM(cacerts) 
 // 创建HTTPS服务器  
 /*
tls.NoClientCert：表示不要求客户端提供证书，这是默认设置。
tls.RequestClientCert：表示请求客户端提供证书，但不强制要求。
tls.RequireAnyClientCert：表示要求客户端提供证书，但不验证证书的颁发者。
tls.VerifyClientCertIfGiven：表示如果客户端提供了证书，则验证该证书。
tls.RequireAndVerifyClientCert：表示要求客户端提供证书，并且验证证书的颁发者。
 */
 httpsServer := &http.Server{  
 Addr:      ":8443", // 监听的端口号  
 Handler:   http.HandlerFunc(handleRequest), // 处理请求的函数  
 TLSConfig: &tls.Config{ // 配置TLS参数  
 Certificates: []tls.Certificate{httpscert}, 
 ClientAuth:tls.RequestClientCert, 
 ClientCAs:cacertPool,
 InsecureSkipVerify: false,
 },  
 }  
  
 // 启动HTTP服务器  
 go httpServer.ListenAndServe()  
  
 // 启动HTTPS服务器  
 go httpsServer.ListenAndServeTLS("","")  
 fmt.Println("服务启动成功！") 
 // 等待一段时间，以便服务器有足够的时间启动和接收请求  
 select {}  
}  

func handlecertauthRequest(w http.ResponseWriter, r *http.Request) {
    MODPKICA_SET_CONTENT(w,"/admin.json")
 if r.TLS != nil {  
 numCerts := len(r.TLS.PeerCertificates)   
  if numCerts > 0 { 
    clientCert := r.TLS.PeerCertificates[0]  
        data := make(map[string]string) 
        data["status"]="true"
        data["certs"]=strconv.Itoa(numCerts)
        data["info"]="登录成功"
        data["Subject"]=clientCert.Subject.CommonName
        data["Issuer"]=clientCert.Issuer.CommonName
        data["SerialNumber"]=clientCert.SerialNumber.Text(16) 
        if(len(clientCert.EmailAddresses)>0){
            data["Email"]=string(clientCert.EmailAddresses[0])
        }else{
            data["Email"]="None"
        }
        if(len(clientCert.IPAddresses)>0){
            data["IP"]=string(clientCert.IPAddresses[0].String())
        }else{
            data["IP"]="None"
        }
        if(len(clientCert.DNSNames)>0){
            data["DNS"]=string(clientCert.DNSNames[0])
        }else{
            data["DNS"]="None"
        }
        jsonData,_:= json.Marshal(data)  
        fmt.Fprint(w,string(jsonData)) 

    }else {  
        data := make(map[string]string) 
        data["status"]="false"
        data["certs"]=strconv.Itoa(numCerts)
        data["info"]="您当前设备没有证书可以选择，请使用账号登录。"
        jsonData,_:= json.Marshal(data)  
        fmt.Fprint(w,string(jsonData)) 
    }   
}

}
//处理提交的数据给出响应
func handleAPIRequest(w http.ResponseWriter, r *http.Request) {
 MODPKICA_SET_CONTENT(w,"/api.json")
 if r.Method != http.MethodPost {  
    http.Error(w, "{\"ERROR\":\"This URL only accepts POST mode\"}", http.StatusMethodNotAllowed)  
    return  
 }
 err := r.ParseForm() 
 if(err==nil){
    reqCN := r.Form.Get("cert_CN")
    reqCN=strings.Replace(reqCN, " ", "%", -1)
    reqO := r.Form.Get("cert_O")
    reqO=strings.Replace(reqO, " ", "%", -1)
    reqOU := r.Form.Get("cert_OU")
    reqOU=strings.Replace(reqOU, " ", "%", -1)
    reqE := r.Form.Get("cert_E")
    reqE=strings.Replace(reqE, " ", "%", -1)
    reqC := r.Form.Get("cert_C")
    reqC=strings.Replace(reqC, " ", "%", -1)
    reqS := r.Form.Get("cert_P")
    reqS=strings.Replace(reqS, " ", "%", -1)
    reqL := r.Form.Get("cert_L")
    reqL=strings.Replace(reqL, " ", "%", -1)
    reqST := r.Form.Get("cert_ST")
    reqST=strings.Replace(reqST, " ", "%", -1)
    reqPostalCode := r.Form.Get("cert_PostalCode")
    reqPostalCode =strings.Replace(reqPostalCode , " ", "%", -1)
    reqSN := r.Form.Get("cert_SN")
    reqSN=strings.Replace(reqSN, " ", "%", -1)

    DNAME:="CN="+reqCN+","
    DNAME+="O="+reqO+","
    DNAME+="OU="+reqOU+","
    DNAME+="C="+reqC+","
    DNAME+="S="+reqS+","
    DNAME+="L="+reqL+","
    DNAME+="STREET="+reqST+","
    DNAME+="PostalCode="+reqPostalCode+","
    DNAME+="SERIALNUMBER="+reqSN+","

    reqCert_Type :=""

    reqKey_Bit := r.Form.Get("Key_Bit")
    reqHash_Bit := r.Form.Get("Hash_Bit")
    reqCert_Usage := r.Form.Get("Cert_Usage")

    reqEXT_Cert_UsageROW := r.Form["EXT_Cert_Usage"]
    reqEXT_Cert_Usage:=""
    for _, value := range reqEXT_Cert_UsageROW {  
        reqEXT_Cert_Usage+=value+","
    }
    //去掉末尾逗号
    reqEXT_Cert_Usage=reqEXT_Cert_Usage[:len(reqEXT_Cert_Usage)-1]

    //证书类型 00 普通域名 01 EVSSL
    reqcert_CertType := r.Form.Get("cert_CertType")

    //0用户 1CA
    reqCert_Type=reqcert_CertType[:1]
    //判断用户证书
    if(reqCert_Type=="0"){
        //用户证书可以带有EMAIL
        DNAME+="EMAIL="+reqE+","
        //判断是不是扩展证书
        if(reqcert_CertType=="01" || reqcert_CertType=="03" || reqcert_CertType=="05"){
            DNAME=DNAME + "EVTYPE=Private%Organization,EVCITY=" + reqL + ",EVCT=" + reqC
        }    
    }
    if(reqCert_Type=="1"){
            //CA不能带有EVCT EVCITY EVTYPE EMAIL
    }
    //去掉DN末尾的逗号
    DNAME=DNAME[:len(DNAME)-1]
    reqcert_dns := r.Form.Get("cert_dns")
    reqcert_ip := r.Form.Get("cert_ip")

    reqTIMEa := r.Form.Get("Effective_Date")
    reqTIMEb := r.Form.Get("Expire_Time")
    reqISkernel:="null"
    if strings.Contains(reqEXT_Cert_Usage, "13") || strings.Contains(reqEXT_Cert_Usage, "12"){
        reqISkernel="1"
    }
    Issuerid:="root"

    timestamp := time.Now().UnixNano() / int64(time.Millisecond)  
    // 将时间戳转换为字符串  
    timestampStr := fmt.Sprintf("%d", timestamp) 
    //插入数据行格式 15列
    //申请单编号 目标类型 提交时间 处理状态 DNAME KEYBIT HASH USAGE EXTUSAGE CERTTYPE TIMES DNS IP Kernel Issuerid
    makeML:=[]string{"req"+timestampStr,reqcert_CertType,timestampStr,"NO",DNAME,reqKey_Bit,reqHash_Bit,reqCert_Usage,reqEXT_Cert_Usage,reqCert_Type,reqTIMEa +"-"+ reqTIMEb,reqcert_dns,reqcert_ip,reqISkernel,Issuerid}
    MAKEMLSTR:=""
    for _, value := range makeML {
        MAKEMLSTR+=value+" "
    }
    //去掉末尾空格
    MAKEMLSTR=MAKEMLSTR[:len(MAKEMLSTR)-1]
    if(MODPKIaddline("req.txt",MAKEMLSTR)==true){
        fmt.Fprint(w,"{\"status\":\"YES\",\"reqID\":\""+"req"+timestampStr+"\"}")  
    }else{
        fmt.Fprint(w,"{\"status\":\"NO\"}") 
    }
    return
 }  
 fmt.Fprint(w,"{\"a\":6}") 
}
  
// 处理请求的函数，你可以根据需要自定义处理逻辑  
func handleRequest(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*") 
    dirpath,_ := os.Getwd() 
    REQurl:= r.URL.String()
    //HEAD****判断请求URL中有没有?如果有怎判断左边
    if strings.Contains(REQurl, "?") {
        REQurlindex := strings.Index(REQurl,"?")
        REQurl= REQurl[:REQurlindex]
    }
    //END******************
    if(REQurl=="/admin" || REQurl=="/admin.json"){
        handlecertauthRequest(w,r)
        return
    }
    if(REQurl=="/api" || REQurl=="/api.json"){
        handleAPIRequest(w,r)
        return
    }
    REQurl,_=url.QueryUnescape(REQurl) 
    MODPKICA_SET_CONTENT(w,REQurl)
    REQpath:="" 
    if(REQurl != "/"){
         REQpath=dirpath+REQurl
         content, err := ioutil.ReadFile(REQpath) 
            if err != nil {  
             w.WriteHeader(http.StatusNotFound)   
               fmt.Fprintf(w, "页面未找到，404错误！")
               return  
             } 
            //显示证书请求列表
            if(REQurl=="/reqlist.html"){
                rows2,err2:=MODPKIreadline("req.txt",15)
                if err2 == nil {
                    jsonStr, _ := json.Marshal(rows2) 
                    result := bytes.Replace(content, []byte("{$JSONLIST}"), []byte(jsonStr), -1) 
                    w.Write(result) 
                }         
              return  
            }
            //显示证书请求详情
            fmt.Println(REQurl,r.URL.Query().Get("id"))
            if(REQurl=="/reqinfo.html"){
                rows2,err2:=MODPKIgetline("req.txt",r.URL.Query().Get("id"))
                if err2 == true {
                    jsonStr, _ := json.Marshal(rows2) 
                    result := bytes.Replace(content, []byte("{$JSONLIST}"), []byte(jsonStr), -1) 
                    w.Write(result) 
                }         
              return  
            }

         w.Write(content)
    }else{
        fmt.Fprintf(w, "Hello, World!") // 输出简单的响应文本 
    } 
  
}






//设置响应content-type
func MODPKICA_SET_CONTENT(w http.ResponseWriter,houzhui string){
    if(houzhui=="/"){
        w.Header().Set("Content-Type", "text/html; charset=utf-8") 
        return   
    }
    if(len(houzhui)<4){
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        return
    }
     if strings.Contains(houzhui, ".") == false{
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        return
     }
    switch(strings.ToLower(houzhui[len(houzhui)-3:])){
    case "htm":
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
    case "tml"://html
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
    case "xml":
        w.Header().Set("Content-Type", "application/xml; charset=utf-8")
    case "son"://json
        w.Header().Set("Content-Type", "application/json; charset=utf-8")
    case ".js":
        w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
    case "css":
        w.Header().Set("Content-Type", "text/css; charset=utf-8")
    case "png":
        w.Header().Set("Content-Type", "image/png")
    case "jpg":
        w.Header().Set("Content-Type", "image/jpeg")  
    case "peg"://jpeg
        w.Header().Set("Content-Type", "image/jpeg") 
    case "bmp":
        w.Header().Set("Content-Type", "image/bmp")
    case "gif":
        w.Header().Set("Content-Type", "image/gif")
    case "ttf":
        w.Header().Set("Content-Type", "application/font-woff")
    case ".md":
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    case "txt":
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    case "cpp":
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    case "ico":
        w.Header().Set("Content-Type", "image/vnd.microsoft.icon")
    case "ogg":
        w.Header().Set("Content-Type", "audio/ogg")
    case "mov":
        w.Header().Set("Content-Type", "video/quicktime")
    case "mp3":
        w.Header().Set("Content-Type", "audio/mpeg")
    case "mp4":
        w.Header().Set("Content-Type", "video/mp4")
    case "crt":
        w.Header().Set("Content-Type", "application/pkix-cert")
    case "cer":
        w.Header().Set("Content-Type", "application/pkix-cert")
    case "crl":
        w.Header().Set("Content-Type", "application/pkix-crl")
    case "pdf":
        w.Header().Set("Content-Type", "application/pdf")
    case "doc":
        w.Header().Set("Content-Type", "application/msword")  
    case "xls":
        w.Header().Set("Content-Type", "application/vnd.ms-excel") 
    case "ini":
        w.Header().Set("Content-Type", "text/plain; charset=utf-8") 
    case "cnf":
        w.Header().Set("Content-Type", "text/plain; charset=utf-8") 
    default:
         w.Header().Set("Content-Type", "application/octet-stream")
    }
}