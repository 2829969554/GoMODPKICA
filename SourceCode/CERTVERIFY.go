package main

import (
    "fmt"
    "crypto"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/ocsp"
gox509 "crypto/x509"
    "tjfoc/gmsm/x509"
    "io/ioutil"
    "bytes"
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
    "crypto/x509/pkix"
    "tjfoc/gmsm/sm2"
    "tjfoc/gmsm/sm3"
    "strings"
    //"crypto/x509/pkix"
)


func showIssuerOrSubject(RawIssuer []byte){  // DER encoded Issuer

    issuerRDNSequence := pkix.RDNSequence{}
    _, err := asn1.Unmarshal(RawIssuer, &issuerRDNSequence)
    if(err != nil){
        fmt.Println("Error:showIssuer解析出错:",err)
        return
    }

    var IssuerName pkix.Name
    IssuerName.FillFromRDNSequence(&issuerRDNSequence)
var attributeTypeNames = map[string]string{
    "2.5.4.6":  "C",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.3":  "CN",
    "2.5.4.5":  "SERIALNUMBER",
    "2.5.4.7":  "L",
    "2.5.4.8":  "ST",
    "2.5.4.9":  "STREET",
    "2.5.4.17": "POSTALCODE",
    "2.5.4.15":"EVTYPE",
    "1.3.6.1.4.1.311.60.2.1.2":"EVCITY",
    "1.3.6.1.4.1.311.60.2.1.3":"EVCT",
    "1.2.840.113549.1.9.1":"EMAIL",
}
    for _, name := range IssuerName.Names {
       switch attributeTypeNames[fmt.Sprintf("%s",name.Type)]{
        case "C":
            //IssuerName.Country[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.Country)>0){
                continue
            }
            IssuerName.Country = append(IssuerName.Country,fmt.Sprintf("%s",name.Value))
        case "O":
            //IssuerName.Organization[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.Organization)>0){
                continue
            }
            IssuerName.Organization = append(IssuerName.Organization,fmt.Sprintf("%s",name.Value))
        case "OU":
            //IssuerName.OrganizationalUnit[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.OrganizationalUnit)>0){
                continue
            }
            IssuerName.OrganizationalUnit = append(IssuerName.OrganizationalUnit,fmt.Sprintf("%s",name.Value))
        case "CN":
            IssuerName.CommonName= fmt.Sprintf("%s",name.Value)
        case "SERIALNUMBER":
            IssuerName.SerialNumber= fmt.Sprintf("%s",name.Value)
        case "L":
            //IssuerName.Locality[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.Locality)>0){
                continue
            }
            IssuerName.Locality = append(IssuerName.Locality,fmt.Sprintf("%s",name.Value))

        case "ST":
            //IssuerName.StreetAddress[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.StreetAddress)>0){
                continue
            }
            IssuerName.StreetAddress = append(IssuerName.StreetAddress,fmt.Sprintf("%s",name.Value))
        case "STREET":
            //IssuerName.StreetAddress[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.StreetAddress)>0){
                continue
            }
            IssuerName.StreetAddress = append(IssuerName.StreetAddress,fmt.Sprintf("%s",name.Value))
        case "POSTALCODE":
            //IssuerName.PostalCode[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.PostalCode)>0){
                continue
            }
            IssuerName.PostalCode = append(IssuerName.PostalCode,fmt.Sprintf("%s",name.Value))
        case "EVCITY":
            //IssuerName.EVCITY[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.EVCITY)>0){
                continue
            }
            IssuerName.EVCITY = append(IssuerName.EVCITY,fmt.Sprintf("%s",name.Value))
        case "EVTYPE":
            //IssuerName.EVTYPE[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.EVTYPE)>0){
                continue
            }
            IssuerName.EVTYPE = append(IssuerName.EVTYPE,fmt.Sprintf("%s",name.Value))
        case "EVCT":
            //IssuerName.EVCT[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.EVCT)>0){
                continue
            }
            IssuerName.EVCT = append(IssuerName.EVCT,fmt.Sprintf("%s",name.Value))
        case "EMAIL":
            //IssuerName.EMAIL[0]= fmt.Sprintf("%s",name.Value)
            if(len(IssuerName.EMAIL)>0){
                continue
            }
            IssuerName.EMAIL = append(IssuerName.EMAIL,fmt.Sprintf("%s",name.Value))
       default:

       }
    }   
        fmt.Println("        CN = ",IssuerName.CommonName)

    
    for _, name := range IssuerName.Country {
        fmt.Println("        C  = ",name)
    }
    for _, name := range IssuerName.Organization {
        fmt.Println("        O  = ",name)
    }
    for _, name := range IssuerName.OrganizationalUnit {
        fmt.Println("        OU = ",name)
    }
    for _, name := range IssuerName.Province {
        fmt.Println("        P  = ",name)
    }
    for _, name := range IssuerName.Locality {
        fmt.Println("        L  = ",name)
    }
    for _, name := range IssuerName.StreetAddress {
        fmt.Println("        Street = ",name)
    }
    for _, name := range IssuerName.EMAIL {
        fmt.Println("        Email  = ",name)
    }

    if(IssuerName.SerialNumber != ""){
        fmt.Println("        注册编号  = ",IssuerName.SerialNumber)
    }
    
    for _, name := range IssuerName.EVCT {
        fmt.Println("        注册国家  = ",name)
    }
    for _, name := range IssuerName.EVCITY {
        fmt.Println("        注册城市  = ",name)
    }
    for _, name := range IssuerName.EVTYPE {
        fmt.Println("     注册业务类别 = ",name)
    }
 
    //未知的OID和值
    for _, name := range IssuerName.ExtraNames {
        fmt.Println("        ",name.Type," = ",name.Value)
    }
    /*
    //未知的OID和值
    for _, name := range IssuerName.Names {
       // fmt.Println(attributeTypeNames[fmt.Sprintf("%s",name.Type)])
        fmt.Println("        ",name.Type," = ",name.Value)
    }
    */
    fmt.Println("")
}

//根据签名算法获取哈希算法名称 和 签名算法名称
func GetHashType(SignatureAlgorithm x509.SignatureAlgorithm)(hash string,key string){
    switch SignatureAlgorithm{
    case x509.MD2WithRSA :
        return "MD2","RSA"
    case x509.MD5WithRSA :
        return "MD5","RSA"
    case x509.SHA1WithRSA :
        return "SHA1","RSA"
    case x509.SHA256WithRSA :
        return "SHA256","RSA"
    case x509.SHA384WithRSA :
        return "SHA384","RSA"
    case x509.SHA512WithRSA :
        return "SHA512","RSA"
    case x509.DSAWithSHA1 :
        return "SHA1","DSA"
    case x509.DSAWithSHA256 :
        return "SHA256","DSA"
    case x509.ECDSAWithSHA1 :
        return "SHA1","ECC"
    case x509.ECDSAWithSHA256 :
        return "SHA256","ECC"
    case x509.ECDSAWithSHA384 :
        return "SHA384","ECC"
    case x509.ECDSAWithSHA512 :
        return "SHA512","ECC"
    case x509.SHA256WithRSAPSS :
        return "SHA256","RSAPSS"
    case x509.SHA384WithRSAPSS :
        return "SHA384","RSAPSS"
    case x509.SHA512WithRSAPSS :
        return "SHA512","RSAPSS"
    case x509.SM2WithSM3 :
        return "SM3","SM2"
    case x509.SM2WithSHA1 :
        return "SHA1","SM2"
    case x509.SM2WithSHA256 :
        return "SHA256","SM2"
    default:
        return "",""
    }
    return "",""
}
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

    fmt.Println("        版本：",dmcert.Version)

    text := fmt.Sprintf("%x", dmcert.SerialNumber)
    if len(text)%2 != 0 {
        text = "0" + text
    }
    HashType,SignType := GetHashType(dmcert.SignatureAlgorithm)
    SignType = SignType
    fmt.Println("      序列号：", text)
    fmt.Println("    签名算法：",dmcert.SignatureAlgorithm)
    fmt.Println("签名哈希算法：",HashType,"\n")
    fmt.Println("颁发者：","")
    showIssuerOrSubject(dmcert.RawIssuer)

    fmt.Println("有效期从：",dmcert.NotBefore)
    fmt.Println("有效期到：",dmcert.NotAfter,"\n")

    fmt.Println("使用者：","")
    showIssuerOrSubject(dmcert.RawSubject)

    switch dmcert.PublicKeyAlgorithm {
    case 1:
            fmt.Println("    公钥：","RSA",dmcertPublicKey.(*rsa.PublicKey).Size()*8)
    case 3:
        // 获取椭圆曲线
        curve := dmcertPublicKey.(*ecdsa.PublicKey).Curve
        // 根据椭圆曲线确定密钥位数
        switch curve {
        case elliptic.P256():
            fmt.Println("    公钥：","ECC 256")
        case elliptic.P384():
            fmt.Println("    公钥：","ECC 384")
        case elliptic.P521():
            fmt.Println("    公钥：","ECC 521")
        default:
            fmt.Println("    公钥：","SM2 256")
        }

    default:
            fmt.Println("    公钥：","未知",dmcert.PublicKeyAlgorithm)
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
        case fmt.Sprintf("%x",asn1.ObjectIdentifier{1,3,6,1,4,1,311,2,1,22}):
            fmt.Println("              Windows 商业代码签名 (",ExtKeyUsage,")")
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
    fmt.Println("证书签名：\n        ",hex.EncodeToString(dmcert.Signature),"\n")

    if(fmt.Sprintf("%x",dmcert.RawSubject) == fmt.Sprintf("%x",dmcert.RawIssuer)){
        fmt.Println("证书类别： 根证书\n")
        go CheckSign(dmcertPublicKey,dmcert.RawTBSCertificate,dmcert.SignatureAlgorithm,dmcert.Signature)
    }else{
        fmt.Println("证书类别： 非根证书\n")
        fmt.Println("证书链： ")
        CheckSign(GetSubPublicKey(dmcert.IssuingCertificateURL),dmcert.RawTBSCertificate,dmcert.SignatureAlgorithm,dmcert.Signature)
    }
    fmt.Printf("证书状态：")

    //证书已过期，或者尚未生效。"
    if(time.Now().Before(dmcert.NotBefore) || time.Now().Before(dmcert.NotBefore)){
       fmt.Println("该证书已过期，或者尚未生效。")  
    }else{
        CheckCRL(dmcert.SerialNumber,dmcert.CRLDistributionPoints)
        CheckOCSP(dmcert.SerialNumber,dmcert.OCSPServer,dmcert)
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

//检查在线证书状态协议
func CheckOCSP(certid *big.Int,OCSP_URL []string,dmcert *x509.Certificate)(CertIsok bool){
    if(len(OCSP_URL) == 0  || OCSP_URL== nil){
        fmt.Println("        OCSP无法检查吊销状态 |错误原因：证书扩展中没有OCSP URL地址~ ","\n")
        return false
    }
    var cert,issuercert gox509.Certificate
    cert.SerialNumber = certid
    issuercert.RawSubjectPublicKeyInfo = dmcert.RawSubjectPublicKeyInfo
    issuercert.RawSubject = dmcert.RawIssuer
    reqByte,err := ocsp.CreateRequest(&cert,&issuercert,nil)
    if err != nil {
        fmt.Println("          OCSP无法检查吊销状态 |错误原因：Error Create the request: ", "\n")
        return false
    }

    httpRequest, err2 := http.NewRequest(http.MethodPost, OCSP_URL[0], bytes.NewBuffer(reqByte))
    if err2 != nil {
        fmt.Println("          OCSP无法检查吊销状态 |错误原因：Error pre-post the request: ", "\n")
        return false
    } 
    httpRequest.Header.Add("Content-Type", "application/ocsp-request")
    httpRequest.Header.Add("Accept", "application/ocsp-response")

    // 发送请求
    httpClient := &http.Client{}
    httpResponse, err3 := httpClient.Do(httpRequest)
    if err3 != nil {
        fmt.Println("          OCSP无法检查吊销状态 |错误原因：Error post the request: ", "\n")
        return false
    }
    defer httpResponse.Body.Close()
    // 读取响应
    output, err4 := ioutil.ReadAll(httpResponse.Body)
    if err4 != nil {
        fmt.Println("          OCSP无法检查吊销状态 |错误原因：Error Reading the response: ", "\n")
        return false
    }
    response,err5 := ocsp.ParseResponse(output,nil)
    if err5 != nil {
        fmt.Println("          OCSP无法检查吊销状态 |错误原因：Error Parsing the response: ", "\n")
        return false
    }
    if(response.Status == 0){
        fmt.Println("          证书正常。（OCSP）")
        return true
    }
    if(response.Status == 1){
        fmt.Println("          此证书已被颁发机构吊销。（OCSP）吊销时间：",response.RevokedAt,"原因:",response.RevocationReason)
        return false
    }
    if(response.Status == 2){
        fmt.Println("          证书未知。（OCSP）")
        return false
    }
    
    return false

}

//检查证书吊销列表
func CheckCRL(certid *big.Int,CRL_URL []string)(CertIsok bool){
    if(len(CRL_URL) == 0  || CRL_URL== nil){
        fmt.Println("CRL无法检查吊销状态 |错误原因：证书扩展中没有CRL URL地址~ ","\n")
        return false
    }
    // 发起 HTTP GET 请求
    resp, err := http.Get(CRL_URL[0])
    if err != nil {
        // 如果请求失败，打印错误信息
        fmt.Println("CRL无法检查吊销状态 |错误原因：Error fetching the URL: ", "\n")
        return false
    }
    defer resp.Body.Close()

    // 读取响应体内容
    contents, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        // 如果读取失败，打印错误信息
        fmt.Println("CRL无法检查吊销状态 |错误原因：Error reading the response: ","\n")
        return false
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
        fmt.Println("CRL无法检查吊销状态 |错误原因：Failed to parse CRL: ","\n")
        return false
    }

    revokedCerts := crl.TBSCertList.RevokedCertificates
    for _, revokedCert := range revokedCerts {
        if(certid.Cmp(revokedCert.SerialNumber) ==0){
            fmt.Println("此证书已被颁发机构吊销。（CRL） 吊销时间：",revokedCert.RevocationTime)
            return true
        }      
    }
    fmt.Println("证书正常。（CRL）")
    return false
}


//获取颁发者证书公钥
func GetSubPublicKey(CRTurl []string)(SubPublicKey interface{}){
    if(len(CRTurl) == 0  || CRTurl== nil){
        fmt.Println("验证签名： 无法验证签名 |错误原因：证书扩展中没有URL地址，无法找到上级证书链~ ","\n")
        return nil
    }
    // 发起 HTTP GET 请求
    resp, err := http.Get(CRTurl[0])
    if err != nil {
        // 如果请求失败，打印错误信息
        fmt.Println("验证签名： 失败 |错误原因：Error fetching the URL: ","\n")
        return nil
    }
    defer resp.Body.Close()

    // 读取响应体内容
    contents, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        // 如果读取失败，打印错误信息
        fmt.Println("验证签名： 失败 |错误原因：Error reading the response: ","\n")
        return nil
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
        fmt.Println("解析CA证书失败")
        return nil
    }

    if(fmt.Sprintf("%x",dmcacert.RawSubject) != fmt.Sprintf("%x",dmcacert.RawIssuer)){
        fmt.Println("       CA   -->",fmt.Sprintf("%x",dmcacert.SubjectKeyId))
        if(len(dmcacert.IssuingCertificateURL) != 0){
            GetSubPublicKey(dmcacert.IssuingCertificateURL)
        }else{
            fmt.Println(" 无法链接到可信根证书 | 错误原因：证书扩展中没有颁发者URL地址，无法找到CA的上级证书链。\n")
            fmt.Println("信任状态： 不可信 (由于无法找到上级证书链 或 Root 根证书不在“受信任的根证书颁发机构”存储区中，所以它不受信任。)\n") 
            return nil
        }
        
    }else{
        fmt.Println("       Root -->",fmt.Sprintf("%x",dmcacert.SubjectKeyId))
        if(fmt.Sprintf("%x",dmcacert.SubjectKeyId) == "66baba33e30f6ce13cee79f9b203191176136666ef4299d42ed1778d9050e890"){
           fmt.Println("信任状态： 可信 (此证书成功链接到信任锚[Root根证书])\n")  
        }else{
           fmt.Println("信任状态： 不可信 (由于 Root 根证书不在“受信任的根证书颁发机构”存储区中，所以它不受信任。)\n") 
        }

    }
    dmcaPublicKey,err3 := x509.ParsePKIXPublicKey(dmcacert.RawSubjectPublicKeyInfo)
    if err3 != nil {
        fmt.Println("解析CA公钥失败：",err3)
        return nil
    }
    return dmcaPublicKey
}

//验证证书签名
func CheckSign(pubkey interface{},PreSignData []byte,SignatureAlgorithm x509.SignatureAlgorithm,Signature []byte)(SignatureIsOK bool){
    if(pubkey == nil){
        return false
    }
    HashTypeName,SignTypeName := GetHashType(SignatureAlgorithm)
    //fmt.Println(HashTypeName,SignTypeName)
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
    switch HashTypeName {

    case "SHA512":
        hash = crypto.SHA512
        Hashsha512 := sha512.New()
        Hashsha512.Write(PreSignData)
        result = Hashsha512.Sum(nil)

    case "SHA384":
        hash = crypto.SHA384
        Hashsha384 := sha512.New384()
        Hashsha384.Write(PreSignData)
        result = Hashsha384.Sum(nil)

    case "SHA256":
        hash = crypto.SHA256
        Hashsha256 := sha256.New()
        Hashsha256.Write(PreSignData)
        result = Hashsha256.Sum(nil)

    case "SHA1":
        hash = crypto.SHA1
        Hashsha1 := sha1.New()
        Hashsha1.Write(PreSignData)
        result = Hashsha1.Sum(nil)
    case "MD5":
        hash = crypto.MD5
        Hashmd5 := md5.New()
        Hashmd5.Write(PreSignData)
        result = Hashmd5.Sum(nil)
    case "SM3":
        Hashsm3 := sm3.New()
        Hashsm3.Write(PreSignData)
        result = Hashsm3.Sum(nil)
        result = PreSignData
    default:
        fmt.Println("验证签名： 失败 |错误原因：未知签名算法\n",SignatureAlgorithm,"\n")
        return false
    }

    if(SignTypeName == "RSA"){
        certIsok:=rsa.VerifyPKCS1v15(pubkey.(*rsa.PublicKey),hash,result,Signature)
        if(certIsok == nil){
            fmt.Println("验证签名： 通过、签名有效\n")
            return true
        }else{
            fmt.Println("验证签名： 签名无效\n",certIsok)
        }
    }

    if(SignTypeName == "ECC"){
        certIsok := ecdsa.VerifyASN1(pubkey.(*ecdsa.PublicKey), result, Signature)
        if(certIsok){
            fmt.Println("验证签名： 通过、签名有效\n")
            return true
        }else{
            fmt.Println("验证签名： 签名无效","，可能文件已经被修改。\n")
        }
    }
    if(SignTypeName == "SM2"){

        var sm2pubkey *sm2.PublicKey
        sm2pubByte,_ := x509.MarshalPKIXPublicKey(pubkey.(*ecdsa.PublicKey))
        //拼装SM2公钥HEX
        splitStr := strings.Split(fmt.Sprintf("%x",sm2pubByte), "04")
        if(len(splitStr)==2){
            sm2pub,err := x509.ReadPublicKeyFromHex("04" + splitStr[1])
            if(err != nil){
                fmt.Println(err)
            }
            sm2pubkey = sm2pub
        }
        certIsok := sm2pubkey.Verify(result, Signature)
        if(certIsok){
            fmt.Println("验证签名： 通过、签名有效\n")
            return true
        }else{
            fmt.Println("验证签名： 签名无效","，可能文件已经被修改。\n")
        }
        
    }
    return false
}