package main

import (
    "fmt"
    "log"
    "crypto/rand"
    //"crypto/x509/pkix"
    "modcrypto/x509"
    //oldx509 "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "encoding/asn1"
    "math/big"
    "time"
    "io/ioutil"
    "modcrypto/gm/sm2"
    "modcrypto/hash/sm3"
    "net"
    "encoding/hex"
    "encoding/binary"
    "os"
    "io"
)


// PolicyInformation 定义了证书策略信息结构
type PolicyInformation struct {
    PolicyIdentifier asn1.ObjectIdentifier
    PolicyQualifiers []PolicyQualifierInfo
}
// PolicyQualifierInfo 定义了策略限定符信息结构
type PolicyQualifierInfo struct {
    PolicyQualifierID asn1.ObjectIdentifier
    Qualifier         asn1.RawValue
}
//定义策略限定符用户通告信息
type UserNonice struct{
    Name         asn1.RawValue `asn1:"optional,tag:0"`
}
//设置用户通告文本
func (this *UserNonice) SetText(text string){
      this.Name =asn1.RawValue{
      Class: asn1.ClassUniversal,
      Tag: asn1.TagUTF8String,
      Bytes: []byte(text),
      IsCompound: false,
      }
}
//返回asn1字节集
func (this UserNonice) FullByte() []byte{
      mycccbyte,_ := asn1.Marshal(this)
      return mycccbyte
}
//根据自定义参数生成符合条件的集合体 字节集
//OID列表 cps地址  用户通告
func GenerateCPSbyte(oids []asn1.ObjectIdentifier,cps string,usernonice string)[]byte{
    if((len(oids)>0  && cps != "") || (len(oids)>0  && usernonice != "")){

    policyInfo := PolicyInformation{
        PolicyIdentifier: oids[0],
        PolicyQualifiers: []PolicyQualifierInfo{},
    }

    if(cps != ""){
        var mycps PolicyQualifierInfo
        mycps.PolicyQualifierID = asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,1}
        mycps.Qualifier = asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte(cps), IsCompound: false}
        policyInfo.PolicyQualifiers = append(policyInfo.PolicyQualifiers,mycps)
    }
    if(usernonice != ""){
        var mynonice UserNonice
        mynonice.SetText(usernonice)
        var myusernonice PolicyQualifierInfo
        myusernonice.PolicyQualifierID = asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,2}
        myusernonice.Qualifier = asn1.RawValue{FullBytes: mynonice.FullByte(),}
        policyInfo.PolicyQualifiers = append(policyInfo.PolicyQualifiers,myusernonice )
    }

/*
    var myccc UserNonice
    myccc.SetText(cpsTEXT)
    // 创建PolicyInformation结构
    policyInfo := PolicyInformation{
        PolicyIdentifier: asn1.ObjectIdentifier{2,23,140,1,4,1},
        PolicyQualifiers: []PolicyQualifierInfo{
        {
            PolicyQualifierID: asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,1},
            Qualifier:asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte(cpsURL), IsCompound: false},
        },
        {
            PolicyQualifierID: asn1.ObjectIdentifier{1,3,6,1,5,5,7,2,2},
            Qualifier:         asn1.RawValue{FullBytes: myccc.FullByte(),},
    
        },

        },
    }
*/

    // 将PolicyInformation转换为ASN.1 DER编码
    derPolicyInfo, _ := asn1.Marshal(policyInfo)  
    //遍历出所有OIDS
    var byterow []byte
    if(len(oids)>1){
        for i := 1; i < len(oids); i++ {
            myoid := []asn1.ObjectIdentifier{oids[i],}
            derPolicyInfo, _ := asn1.Marshal(myoid)
            byterow = append(byterow,derPolicyInfo...)      
        }
        //追加所有OIDS项目
        derPolicyInfo = append(derPolicyInfo, byterow...)   
    }
        derlen := len(derPolicyInfo)
        cps1 := []byte{0x30}
        if(derlen <= 127){
             cps1 = append(cps1,byte(derlen))
             cps1 = append(cps1, derPolicyInfo...)
        }
        if(derlen < 256  && derlen > 127){
             cps1 = append(cps1,0x81)
             cps1 = append(cps1,byte(derlen))
             cps1 = append(cps1, derPolicyInfo...)
        }
        if(derlen > 255){
             bytes := make([]byte, 2)
             binary.BigEndian.PutUint16(bytes, uint16(derlen))
             cps1 = append(cps1,0x82)
             cps1 = append(cps1,bytes...)
             cps1 = append(cps1, derPolicyInfo...)
        } 
             return cps1    
    }else{
        //遍历出所有OIDS
        var byterow []byte
        for i := 0; i < len(oids); i++ {
            myoid := []asn1.ObjectIdentifier{oids[i],}
            derPolicyInfo, _ := asn1.Marshal(myoid)
            //追加所有OIDS项目
            byterow = append(byterow,derPolicyInfo...)
         
        }
        derPolicyInfo := byterow
        derlen := len(derPolicyInfo)
        cps1 := []byte{0x30}
        if(derlen <= 127){
             cps1 = append(cps1,byte(derlen))
             cps1 = append(cps1, derPolicyInfo...)
        }
        if(derlen < 256  && derlen > 127){
             cps1 = append(cps1,0x81)
             cps1 = append(cps1,byte(derlen))
             cps1 = append(cps1, derPolicyInfo...)
        }
        if(derlen > 255){
             bytes := make([]byte, 2)
             binary.BigEndian.PutUint16(bytes, uint16(derlen))
             cps1 = append(cps1,0x82)
             cps1 = append(cps1,bytes...)
             cps1 = append(cps1, derPolicyInfo...)
        }

             return cps1    
    }
                fmt.Println("ERROR：func GenerateCPSbyte() 参数不足")
                 os.Exit(0)
                 return []byte{0}     
}
func GenerateSM2Key() *sm2.PrivateKey {
    privateKey, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        log.Fatalf("failed to generate private key: %v", err)
    }
    // 将SM2私钥编码为DER格式
    prikey,_:=sm2.MarshalPrivateKey(privateKey)
    pubkey,_ :=sm2.MarshalPublicKey(&privateKey.PublicKey)

    pripemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: prikey})
    ioutil.WriteFile("sm2.pem", pripemBytes, 0644)

    pubpemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubkey})
    ioutil.WriteFile("sm2pub.pem", pubpemBytes, 0644)

    return privateKey
}

func CreateSelfSignedSM2Certificate(key *sm2.PrivateKey) []byte {

    // 创建一个字节切片来存储随机数
    buf := make([]byte, 13)

    // 从rand.Reader读取随机数填充到buf中
    io.ReadFull(rand.Reader, buf)
    // 将字节切片转换为大整数
    randomInt := new(big.Int)
    randomInt.SetBytes(buf)
    fmt.Println("SerialNumber:",randomInt)
    hash:=sm3.New()
    hash.Write(sm2.PublicKeyTo(&key.PublicKey))
    sm3sign := hash.Sum(nil)

    // 定义CPS的URL
    cpsURL := "https://d.symcb.com/cps"
    cpsTEXT:= `
                ‌使用者协议‌

本协议由以下两方于____年____月____日签订：

甲方（卖方）：__________________________
地址：__________________________________
联系方式：______________________________

乙方（买方）：__________________________
地址：__________________________________
联系方式：______________________________

鉴于甲方同意出售，乙方同意购买以下商品，双方根据平等、自愿原则，达成如下协议：

‌商品信息‌：

商品名称：__________________________
规格型号：__________________________
数量：______________________________
单价：______________________________
总价：_________（大写：）

‌付款方式与时间‌：
乙方应于____年____月____日前，通过以下方式支付全部款项：______________________。

‌交货时间与方式‌：
甲方应于____年____月____日前，将商品交付至以下地址：，交货方式为：。

‌质量保证与售后服务‌：
甲方保证所售商品为全新、未使用过的，并符合国家相关质量标准。商品自交付之日起____天内，如因非人为原因出现质量问题，甲方负责免费更换或维修。

‌违约责任‌：
如任何一方违反本协议约定，违约方需向守约方支付违约金，违约金为合同总价的____%。同时，守约方有权要求违约方继续履行合同或解除合同。

‌争议解决‌：
双方因执行本协议发生争议，应首先通过友好协商解决；协商不成时，可提交至甲方所在地人民法院诉讼解决。

‌其他‌：
本协议一式两份，甲乙双方各执一份，自双方签字盖章之日起生效。

甲方（签字/盖章）：__________ 日期：____年____月____日

乙方（签字/盖章）：__________ 日期：____年____月____日

请注意，这只是一个简易版的商品销售协议模板，实际使用时可能需要根据具体情况进行调整，并建议由专业法律人士审核，以确保其合法性和有效性。
    `

//cpsTEXT = ""
//cpsURL = ""
mycps:= pkix.Extension{}
            mycps.Id= asn1.ObjectIdentifier{2,5,29,32}
            mycps.Critical= false
            mycps.Value = GenerateCPSbyte([]asn1.ObjectIdentifier{{2,23,140,1,4,1},{2,23,140,1,4,2},{2,23,140,1,4,3},{2,23,140,1,4,4}},cpsURL,cpsTEXT)

    template := x509.Certificate{
        SerialNumber:randomInt , // 序列号
        Subject: pkix.Name{
            CommonName:"hello",
            Organization:  []string{"My Organization"},
            Country:       []string{"US"},
            Province:      []string{"CA"},
            Locality:      []string{"San Francisco"},
            StreetAddress: []string{"Golden Gate Bridge"},
         //   PostalCode:    []string{"94107"},
          //  EVCT: []string{"CN"},
          //  EVCITY: []string{"BEI JING"},
         //   EVTYPE: []string{"Private Organization"},
         //   EMAIL:[]string{"2829969554@qq.com"},
         //   SerialNumber:"123456789",
        },
        NotBefore: time.Now().AddDate(-10, 0, 0),
        NotAfter:  time.Now().AddDate(1, 0, 0), // 证书有效期1年
        IsCA:false,
        BasicConstraintsValid: true,
        KeyUsage:1|32|64,
        AuthorityKeyId:sm3sign[:],
        SubjectKeyId:sm3sign[:],
   
        DNSNames:[]string{"anqikeji.picp.net","localhost",},
        IPAddresses:[]net.IP{net.ParseIP("127.0.0.1"),},
        ExtKeyUsage:[]x509.ExtKeyUsage{1,2,3,4,5,6,7,},

        ExtraExtensions:[]pkix.Extension{mycps,},
        /*
        PolicyIdentifiers: []asn1.ObjectIdentifier{
                                                    {2,23,140,1,3},
                                                    {2,23,140,1,1},
                                                }, 
        */

    }

    var mysctlist SCTList
    var mysct SCT
    mysct.Version = 0
    mysct.LogID = sm3sign[:]
    mysct.Timestamp = uint64(time.Now().UTC().UnixMilli())
    mysct.Hash = 4
    mysct.Signtype = 3
    mysct.Signature,_ = sm2.Sign(nil,key,sm3sign[:],nil)
    mysct.CreateSCT()
    fmt.Println("长度",len(mysct.Signature),hex.EncodeToString(mysct.Signature))
    
    mysctlist.SCTs = append(mysctlist.SCTs,mysct)
    mysctlist.SCTs = append(mysctlist.SCTs,mysct)
    mysctlist.SCTs = append(mysctlist.SCTs,mysct)

    fmt.Println(len(mysctlist.SCTs))

    a,b:= mysctlist.CreateSCTList()
                fmt.Print("\nopenssl x509 v3扩展配置\n ct_precert_scts=DER:")
                for i := 0; i < len(b); i++ {
                    str := fmt.Sprintf("%x",b[i])
                    if(len(str) < 2){
                        str = "0" + str
                    }
                    
                    if(len(b)-1 == i){
                        fmt.Print(str)
                    }else{
                        fmt.Print(str,":")
                    }
                }
    fmt.Println("\n\n",a,b)
      // 创建一个CT扩展 证书透明度
    ctExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
        Critical: false,
        Value: b   ,
        }
    //向证书模板加入证书透明度信息
    template.ExtraExtensions = []pkix.Extension{
       ctExtension,
    }
    derBytes, err := x509.CreateCertificate(rand.Reader,&template, &template, &key.PublicKey, key)
    if err != nil {
        log.Fatalf("Failed to create certificate: %v", err)
    }

    // PEM编码证书
    //pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
    return derBytes
}


func main() {

    eccKey := GenerateSM2Key()

    certBytes := CreateSelfSignedSM2Certificate(eccKey)
    ioutil.WriteFile("sm2.crt", certBytes, 0644)
    certBytes2,_ :=ioutil.ReadFile("sm2.crt")
    dmcert,_ := x509.ParseCertificate(certBytes2)
    ioutil.WriteFile("sm2NoSign.crt", dmcert.RawTBSCertificate, 0644)

            if(sm2.Verify(&eccKey.PublicKey,dmcert.RawTBSCertificate,dmcert.Signature,nil) == nil){
                fmt.Println("验证成功")
            
            }else{
                fmt.Println("验证失败")
            }

}
