package main

import (
    "fmt"
    "crypto"
    "crypto/sha1"
    "crypto/sha256"
    "tjfoc/gmsm/x509"
    "io/ioutil"
    //"crypto/rand"
    "encoding/hex"
    "encoding/pem"
    "encoding/base64"
    "encoding/asn1"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/elliptic"
    "net/http"
    "os"
    "bufio"
    "time"
    "math/big"
    //"crypto/x509/pkix"
)

func main(){
    if(len(os.Args) <2){
        fmt.Println(" 验证证书签名、证书状态、证书有效性\n","例如 Verify.exe cert.crt")
        os.Exit(0)
    }
    certBytespem,_ :=ioutil.ReadFile(os.Args[1])
    certpem, _ := pem.Decode(certBytespem) 

    var certBytes []byte
    if(certpem != nil){
        certBytes= certpem.Bytes   
    }else{
        certBytes = certBytespem
    }
    
    dmcert,err4 := x509.ParseCertificate(certBytes)
    
    if (err4 != nil){
        fmt.Println("解析用户证书失败：",err4)
    }


    dmcertPublicKey,err4 := x509.ParsePKIXPublicKey(dmcert.RawSubjectPublicKeyInfo)
    if err4 != nil {
        fmt.Println("解析用户公钥失败：",err4)
    }

    fmt.Println("版本：",dmcert.Version)

    text := fmt.Sprintf("%x", dmcert.SerialNumber)
    if len(text)%2 != 0 {
        text = "0" + text
    }
    fmt.Println("序列号：", text)
    fmt.Println("签名算法：",dmcert.SignatureAlgorithm)
    fmt.Println("签名哈希算法：","SHA256")
    fmt.Println("颁发者：","...")
    fmt.Println("有效期从：",dmcert.NotBefore)
    fmt.Println("有效期到：",dmcert.NotAfter)
    fmt.Println("使用者：","...")

    switch dmcert.PublicKeyAlgorithm {
    case 1:
         fmt.Println("公钥：","RSA",dmcertPublicKey.(*rsa.PublicKey).Size()*8)
    case 2:
        // 获取椭圆曲线
        curve := dmcertPublicKey.(*ecdsa.PublicKey).Curve
        // 根据椭圆曲线确定密钥位数
        switch curve {
        case elliptic.P256():
            fmt.Println("公钥：","ECC","密钥位数：256")
        case elliptic.P384():
            fmt.Println("公钥：","ECC","密钥位数：384")
        case elliptic.P521():
            fmt.Println("公钥：","ECC","密钥位数：521")
        default:
            fmt.Println("公钥：","ECC","未知的椭圆曲线")
        }
    default:
        fmt.Println("公钥：","未知",dmcert.PublicKeyAlgorithm)
    }

    fmt.Println("公钥参数：","05 00")
    fmt.Println("公钥数据：\n          ",fmt.Sprintf("%x",dmcert.RawSubjectPublicKeyInfo),"\n")

    fmt.Println("授权密钥标识符  ：",fmt.Sprintf("%x",dmcert.AuthorityKeyId))
    fmt.Println("使用者密钥标识符：",fmt.Sprintf("%x",dmcert.SubjectKeyId),"\n")

    fmt.Println("增强型密钥用法：\n")
    for _, ExtKeyUsage := range dmcert.ExtKeyUsage {
        switch ExtKeyUsage{
        case 0:
            fmt.Println("              任何目的 (2.5.29.37.0)")
        case 1:
            fmt.Println("              服务器身份验证 (1.3.6.1.5.5.7.3.1)")
        case 2:
            fmt.Println("              客户端身份验证 (1.3.6.1.5.5.7.3.2)")
        case 3:
            fmt.Println("              代码签名 (1.3.6.1.5.5.7.3.3)")
        case 4:
            fmt.Println("              安全电子邮件 (1.3.6.1.5.5.7.3.4)")
        case 5:
            fmt.Println("              IP 安全终端系统 (1.3.6.1.5.5.7.3.5)")
        case 6:
            fmt.Println("              IP 安全隧道终止 (1.3.6.1.5.5.7.3.6)")
        case 7:
            fmt.Println("              IP 安全用户 (1.3.6.1.5.5.7.3.7)")
        case 8:
            fmt.Println("              时间戳 (1.3.6.1.5.5.7.3.8)")
        case 9:
            fmt.Println("              OCSP 签名 (1.3.6.1.5.5.7.3.9)")
        case 10:
            fmt.Println("              微软服务器GatedCrypto (1.3.6.1.4.1.311.10.3.3)")
        case 11:
            fmt.Println("              Netscape服务器GatedCrypto (2.16.840.1.113730.4.1)")    
        default:
            fmt.Println("              未知密钥用法 (",ExtKeyUsage,")")
        }
        
    }
    //UnknownExtKeyUsage
    for _, ExtKeyUsage := range dmcert.UnknownExtKeyUsage{
        switch fmt.Sprintf("%x",ExtKeyUsage) {
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,5}):
            fmt.Println("              Windows 硬件驱动程序验证 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,6}):
            fmt.Println("              Windows 系统组件验证 (",ExtKeyUsage,")")    
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,7}):
            fmt.Println("              OEM Windows 系统组件验证 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,8}):
            fmt.Println("              内嵌 Windows 系统组件验证 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,61,1,1}):
            fmt.Println("              内核模式代码签名 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,64,1,1}):
            fmt.Println("              域名系统(DNS)服务器信任 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,47,1,1}):
            fmt.Println("              系统健康身份认证 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,19}):
            fmt.Println("              已吊销列表签名者 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,5,2,3,5}):
            fmt.Println("              KDC 身份认证 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,13}):
            fmt.Println("              生存时间签名 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,21,5}):
            fmt.Println("              私钥存档 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{2,5,29,32,0}):
            fmt.Println("              所有颁发策略 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,121}):
            fmt.Println("              所有颁发应用程序策略 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,10}):
            fmt.Println("              合格的部署 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,11}):
            fmt.Println("              密钥恢复 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,12}):
            fmt.Println("              文档签名 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,2}):
            fmt.Println("              Microsoft 时间戳 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,4}):
            fmt.Println("              加密文件系统 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,21,6}):
            fmt.Println("              密钥恢复代理 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,21,19}):
            fmt.Println("              目录服务电子邮件复制 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,5,5,8,2,2}):
            fmt.Println("              IP 安全 IKE 中级 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,4,1}):
            fmt.Println("              文件恢复 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,3,9}):
            fmt.Println("              根列表签名者 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,5,1}):
            fmt.Println("              数字权利 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,6,1}):
            fmt.Println("              密钥数据包许可证 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,6,2}):
            fmt.Println("              许可证服务器验证 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,20,1}):
            fmt.Println("              CTL 用法 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,20,2,1}):
            fmt.Println("              证书申请代理 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,20,2,2}):
            fmt.Println("              智能卡登录 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,21,30}):
            fmt.Println("              智能卡已验证 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,21,31}):
            fmt.Println("              智能卡证书已验证 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,21,32}):
            fmt.Println("              智能卡信任使用 (",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,2,840,113635,100,4,1}):
            fmt.Println("              Apple CodeSing 代码签名(",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,2,840,113635,100,4,1,1}):
            fmt.Println("              Apple Development CodeSing 开发者代码签名(",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,2,840,113635,100,4,1,4}):
            fmt.Println("              Apple Resource Signing 资源签名(",ExtKeyUsage,")")
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,2,840,113635,100,4,2}):
            fmt.Println("              Apple Ichat Signing Ichat签名(",ExtKeyUsage,")")

        default:
            fmt.Println("              未知密钥用法 (",ExtKeyUsage,")")
        }
      
    }

    fmt.Println("\n使用者可选名称：")
    for _, DNSNames := range dmcert.DNSNames {
        fmt.Println("              DNS = ",DNSNames)
    }
    for _, EmailAddresses := range dmcert.EmailAddresses {
        fmt.Println("              Email = ",EmailAddresses)
    }
    for _, IPAddresses := range dmcert.IPAddresses {
        fmt.Println("              IP = ",IPAddresses)
    }
    fmt.Println("授权信息访问：")
    for _, IssuingCertificateURL := range dmcert.IssuingCertificateURL {
        fmt.Println("              颁发者 URL=",IssuingCertificateURL)
    }
    for _, OCSPServer := range dmcert.OCSPServer {
        fmt.Println("              OCSP   URL=",OCSPServer)
    }

    fmt.Println("证书吊销列表：")
    for _, CRLDistributionPoint := range dmcert.CRLDistributionPoints {
        fmt.Println("              CRL分发点 = ",CRLDistributionPoint)
    }

    fmt.Println("密钥用法：",dmcert.KeyUsage)

    if(dmcert.BasicConstraintsValid){
        //Path Length Constraint -1 代表 None ,无限制
        if(dmcert.IsCA){
            fmt.Println("基本约束(关键)：\n              Subject Type=CA  \n              Path Length Constraint = ",dmcert.MaxPathLen)
        }else{
            fmt.Println("基本约束(关键)：\n              Subject Type=End Entity  \n              Path Length Constraint = ",dmcert.MaxPathLen)
        }
        
    }else{
        if(dmcert.IsCA){
            fmt.Println("基本约束：\n              Subject Type=CA  \n              Path Length Constraint = ",dmcert.MaxPathLen)
        }else{
            fmt.Println("基本约束：\n              Subject Type=End \n              Entity  Path Length Constraint = ",dmcert.MaxPathLen)
        }
    }
    
    fmt.Println("证书策略：")
    for _, PolicyIdentifiers := range dmcert.PolicyIdentifiers {

        switch fmt.Sprintf("%x",PolicyIdentifiers){
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{2,23,140,1,3}):
            fmt.Println("              Extended Validation(扩展验证，代码签名) OID = ",PolicyIdentifiers)
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{2,23,140,1,4,1}):
            fmt.Println("              Code Signing(代码签名)                  OID = ",PolicyIdentifiers)
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{2,23,140,1,1}):
            fmt.Println("              Extended Validation(扩展验证，SSL)      OID = ",PolicyIdentifiers)
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{2,23,140,1,2,2}):
            fmt.Println("              Organization Validation(组织验证)       OID = ",PolicyIdentifiers)
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{2,23,140,1,2,1}):
            fmt.Println("              Domain Validation(域名验证)             OID = ",PolicyIdentifiers)   
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{2,23,140,1,2,3}):
            fmt.Println("              Individuals Validation(个人验证)        OID = ",PolicyIdentifiers) 


        case fmt.Sprintf("%x",asn1.ObjectIdentifier{2,5,29,32,0}):
            fmt.Println("              所有颁发策略           OID = ",PolicyIdentifiers)
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,10,12,1}):
            fmt.Println("              所有应用程序策略       OID = ",PolicyIdentifiers)
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,1}):
            fmt.Println("              证书实践声明指针(Practices Statement)      OID = ",PolicyIdentifiers)
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,2}):
            fmt.Println("              用户通告(User Notice)       OID = ",PolicyIdentifiers)
        default:
            if(len(PolicyIdentifiers) >=6){
                if(PolicyIdentifiers[0]==1 && PolicyIdentifiers[1]==3  && PolicyIdentifiers[2]==6 && PolicyIdentifiers[3]==1 && PolicyIdentifiers[4]==4 && PolicyIdentifiers[5]==1){
                    fmt.Println("              证书颁发策略(Statement Identifier)      OID = ",PolicyIdentifiers)
                    break;
                }
            }

            fmt.Println("              OID = ",PolicyIdentifiers)
            
        }
    }



    fmt.Println("\n\n")
    fmt.Println("证书签名：\n             ",hex.EncodeToString(dmcert.Signature),"\n")

    if(fmt.Sprintf("%x",dmcert.RawSubject) == fmt.Sprintf("%x",dmcert.RawIssuer)){
        fmt.Println("证书类别： 根证书\n")
        CheckSign(dmcertPublicKey,dmcert.RawTBSCertificate,dmcert.SignatureAlgorithm,dmcert.Signature)
    }else{
        fmt.Println("证书类别： 非根证书\n")
        fmt.Println("证书链： ")
        CheckSign(GetSubPublicKey(dmcert.IssuingCertificateURL),dmcert.RawTBSCertificate,dmcert.SignatureAlgorithm,dmcert.Signature)
    }
    fmt.Printf("证书状态： ")

    //证书已过期，或者尚未生效。"
    if(time.Now().Before(dmcert.NotBefore) || time.Now().Before(dmcert.NotBefore)){
       fmt.Println("该证书已过期，或者尚未生效。\n")  
    }else{
           if(CheckCRL(dmcert.SerialNumber,dmcert.CRLDistributionPoints)){
        fmt.Printf("吊销状态异常，此证书已经被颁发机构吊销。\n")
    }else{
        fmt.Printf("证书正常 \n")
    }
    }



  hashsha1:=sha1.New()
  hashsha1.Write(dmcert.RawSubjectPublicKeyInfo)
  Pubkeysha1:=hashsha1.Sum(nil)
  hashsha256:=sha256.New()
  hashsha256.Write(dmcert.RawSubjectPublicKeyInfo)
  Pubkeysha256:=hashsha256.Sum(nil)
  fmt.Println("")
  fmt.Println("密钥 Id 哈希(SHA1)          ： ",fmt.Sprintf("%x",Pubkeysha1))
  fmt.Println("密钥 Id 哈希(Pin-SHA256)    ： ",base64.StdEncoding.EncodeToString(Pubkeysha256))
  fmt.Println("密钥 Id 哈希(Pin-SHA256-Hex)： ",fmt.Sprintf("%x",Pubkeysha256))
  fmt.Println("\n")

  hashsha1=sha1.New()
  hashsha1.Write(dmcert.Raw)
  Pubkeysha1=hashsha1.Sum(nil)
  hashsha256=sha256.New()
  hashsha256.Write(dmcert.Raw)
  Pubkeysha256=hashsha256.Sum(nil)

  fmt.Println("证书哈希(SHA1)              ： ",fmt.Sprintf("%x",Pubkeysha1))
  fmt.Println("证书哈希(SHA256)            ： ",fmt.Sprintf("%x",Pubkeysha256))

  hashsha256=sha256.New()
  hashsha256.Write(dmcert.RawTBSCertificate)
  Pubkeysha256=hashsha256.Sum(nil)
  fmt.Println("签名哈希                    ： ",fmt.Sprintf("%x",Pubkeysha256))

  
  fmt.Printf("\nPress Enter to continue...")
  bufio.NewReader(os.Stdin).ReadBytes('\n')

}


func CheckCRL(certid *big.Int,CRL_URL []string)(CertIsok bool){
    if(len(CRL_URL) == 0  || CRL_URL== nil){
        fmt.Println("无法验证吊销状态 |错误原因：证书扩展中没有证书吊销列表URL地址~ ","\n")
        return
    }
    // 发起 HTTP GET 请求
    resp, err := http.Get(CRL_URL[0])
    if err != nil {
        // 如果请求失败，打印错误信息
        fmt.Println("无法验证吊销状态 |错误原因：Error fetching the URL: ", err,"\n")
        return
    }
    defer resp.Body.Close()

    // 读取响应体内容
    contents, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        // 如果读取失败，打印错误信息
        fmt.Println("无法验证吊销状态 |错误原因：Error reading the response: ", err,"\n")
        return
    }

    crlBytespem := contents
    var crlBytes []byte
    block, _ := pem.Decode(crlBytespem)
    if(block!=nil){
        crlBytes = block.Bytes
    }else{
        crlBytes =  crlBytespem
    }

    // 解析CRL数据
    crl, err := x509.ParseCRL(crlBytes)
    if err != nil {
        fmt.Println("无法验证吊销状态 |错误原因：Failed to parse CRL: %v", err,"\n")
        return
    }

    revokedCerts := crl.TBSCertList.RevokedCertificates
    for _, revokedCert := range revokedCerts {
        if(certid.Cmp(revokedCert.SerialNumber) ==0){
            return true
        }      
    }
    return false
}


//获取颁发者证书公钥
func GetSubPublicKey(CRTurl []string)(SubPublicKey interface{}){
    if(len(CRTurl) == 0  || CRTurl== nil){
        fmt.Println("验证签名： 无法验证签名 |错误原因：证书扩展中没有URL地址，无法找到上级证书链~ ","\n")
        return
    }
    // 发起 HTTP GET 请求
    resp, err := http.Get(CRTurl[0])
    if err != nil {
        // 如果请求失败，打印错误信息
        fmt.Println("验证签名： 失败 |错误原因：Error fetching the URL: ", err,"\n")
        return
    }
    defer resp.Body.Close()

    // 读取响应体内容
    contents, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        // 如果读取失败，打印错误信息
        fmt.Println("验证签名： 失败 |错误原因：Error reading the response: ", err,"\n")
        return
    }

    caBytespem := contents
    capem, _ := pem.Decode(caBytespem) 
    var caBytes []byte
    if(capem != nil){
        caBytes= capem.Bytes
    }else{
        caBytes = caBytespem
    }

    dmcacert,err5 := x509.ParseCertificate(caBytes)
    if (err5 != nil){
        fmt.Println("解析CA证书失败：",err5)
    }

    if(fmt.Sprintf("%x",dmcacert.RawSubject) != fmt.Sprintf("%x",dmcacert.RawIssuer)){
        if(len(dmcacert.IssuingCertificateURL) != 0){
            fmt.Println("CA",fmt.Sprintf("%x",dmcacert.SubjectKeyId))
            GetSubPublicKey(dmcacert.IssuingCertificateURL)
        }else{
            fmt.Println("验证签名： 无法验证签名 |错误原因：证书扩展中没有URL地址，无法找到上级证书链~ \n")
            return false
        }
        
    }else{
        fmt.Println("Root",fmt.Sprintf("%x",dmcacert.SubjectKeyId))
        if(fmt.Sprintf("%x",dmcacert.SubjectKeyId) == "66baba33e30f6ce13cee79f9b203191176136666ef4299d42ed1778d9050e890"){
           fmt.Println("信任状态： 可信 (此Root根证书包含在可信证书库)\n")  
        }else{
           fmt.Println("信任状态： 不可信 (由于CA 根证书不在“受信任的根证书颁发机构”存储区中，所以它不受信任。)\n") 
        }

    }

    dmcaPublicKey,err3 := x509.ParsePKIXPublicKey(dmcacert.RawSubjectPublicKeyInfo)
    if err3 != nil {
        fmt.Println("解析CA公钥失败：",err3)
    }
    return dmcaPublicKey
}

//验证证书签名
func CheckSign(pubkey interface{},PreSignData []byte,SignatureAlgorithm x509.SignatureAlgorithm,Signature []byte)(SignatureIsOK bool){
    if(pubkey == nil){
        return false
    }
/*
    MD2WithRSA
    MD5WithRSA
    //  SM3WithRSA reserve
    SHA1WithRSA
    SHA256WithRSA
    SHA384WithRSA
    SHA512WithRSA
    DSAWithSHA1
    DSAWithSHA256
    ECDSAWithSHA1
    ECDSAWithSHA256
    ECDSAWithSHA384
    ECDSAWithSHA512
    SHA256WithRSAPSS
    SHA384WithRSAPSS
    SHA512WithRSAPSS
    SM2WithSM3
    SM2WithSHA1
    SM2WithSHA256
*/

    var result []byte
    var hash crypto.Hash
    switch SignatureAlgorithm {
    case x509.SHA256WithRSA:
        hash = crypto.SHA256
        Hashsha256 := sha256.New()
        Hashsha256.Write(PreSignData)
        result = Hashsha256.Sum(nil)
    case x509.SHA1WithRSA:
        hash = crypto.SHA1
        Hashsha1 := sha1.New()
        Hashsha1.Write(PreSignData)
        result = Hashsha1.Sum(nil)
    default:
        fmt.Println("验证签名： 失败 |错误原因：未知签名算法\n",SignatureAlgorithm,"\n")
        return false
    }
    certIsok:=rsa.VerifyPKCS1v15(pubkey.(*rsa.PublicKey),hash,result,Signature)
    if(certIsok==nil){
        fmt.Println("验证签名： 通过 | 正常\n")
        return true
    }else{
        fmt.Println("验证签名： 签名无效\n",certIsok)
    }
    return false
}