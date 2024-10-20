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
    "io"
)


func GenerateSM2Key() *sm2.PrivateKey {
    privateKey, err := sm2.GenerateKey(rand.Reader)
    if err != nil {
        log.Fatalf("failed to generate private key: %v", err)
    }
    // 将SM2私钥编码为DER格式
    prikey,_:=sm2.MarshalPrivateKey(privateKey)
    pubkey,_ :=sm2.MarshalPublicKey(&privateKey.PublicKey)

    // 将DER格式私钥PEM编码后写出到文件
    pripemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: prikey})
    ioutil.WriteFile("sm2.pem", pripemBytes, 0644)

    // 将DER格式公钥PEM编码后写出到文件
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

    // 定义CPSP的URL
    cpsURL := "https://d.symcb.com/cps"
    cpsTEXT:= `你好`
    //定义pkix扩展 类型证书策略
    mycps:= pkix.Extension{
        Id: asn1.ObjectIdentifier{2,5,29,32},
        Critical: false,
        Value: GenerateCPSbyte([]asn1.ObjectIdentifier{{2,23,140,1,4,1},{2,23,140,1,4,2}},cpsURL,cpsTEXT),
    }

    //定义X509证书模板
    template := x509.Certificate{
        SerialNumber:randomInt , // 序列号
        Subject: pkix.Name{
            CommonName:"hello",
            Organization:  []string{"My Organization"},
            Country:       []string{"US"},
            Province:      []string{"CA"},
            Locality:      []string{"San Francisco"},
            
            /*
            StreetAddress: []string{"Golden Gate Bridge"},
            PostalCode:    []string{"94107"},
            EVCT: []string{"CN"},
            EVCITY: []string{"BEI JING"},
            EVTYPE: []string{"Private Organization"},
            EMAIL:[]string{"2829969554@qq.com"},
            SerialNumber:"123456789",
            */
        },
        NotBefore: time.Now().AddDate(-10, 0, 0),
        NotAfter:  time.Now().AddDate(1, 0, 0), // 证书有效期1年
        IsCA:true,
        BasicConstraintsValid: true,
        KeyUsage:1|32|64,
        AuthorityKeyId:sm3sign[:],
        SubjectKeyId:sm3sign[:],
   
        DNSNames:[]string{"anqikeji.picp.net","localhost",},
        IPAddresses:[]net.IP{net.ParseIP("127.0.0.1"),},
        ExtKeyUsage:[]x509.ExtKeyUsage{1,2,3,4,5,6,7,},


    }

    //定义SCT结构体
    var mysct SCT
    //版本号
    mysct.Version = 0
    //证书透明度日志ID
    mysct.LogID = sm3sign[:]
    //签署实时数据戳UTC时间，精确到毫秒
    mysct.Timestamp = uint64(time.Now().UTC().UnixMilli())
    //等待签名数据的哈希算法 0:none  1:MD5  2:SHA1  3:SHA224  4:SHA256   5:SHA384  6:SHA512
    mysct.Hash = 4
    //签名算法 0:anonymous  1:RSA  2:DSA  3:ECDSA
    mysct.Signtype = 3
    //签名内容
    mysct.Signature,_ = sm2.Sign(nil,key,sm3sign[:],nil)
    //根据上述参数创建SCT结构数据
    mysct.CreateSCT()

    //定义并创建SCT列表结构体数据
    var mysctlist SCTList
    mysctlist = SCTList{
        //将2组SCT结构套在一起
        SCTs: []SCT{mysct,mysct},
    }

    //生成SCT列表 ASN.1数据  status是状态True|False   sctans1data为 SCT列表的ASN.1数据
    status,sctans1data:= mysctlist.CreateSCTList()
    fmt.Print("openssl x509 v3扩展配置\n ct_precert_scts=DER:")
    for i := 0; i < len(sctans1data); i++ {
        str := fmt.Sprintf("%x",sctans1data[i])
        if(len(str) < 2){
            str = "0" + str
        }
                    
        if(len(sctans1data)-1 == i){
           fmt.Print(str)
        }else{
            fmt.Print(str,":")
        }
    }
    fmt.Println("\nSCT列表生成状态：",status)

// 创建一个pkix CT列表扩展 证书透明度
ctExtension := pkix.Extension{
    Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
    Critical: false,
    Value: sctans1data,
}

//统一向证书模板加入上面的pkix扩展信息
template.ExtraExtensions = []pkix.Extension{
    ctExtension,mycps,
}

//根据上述X509证书模板签署证书
derBytes, err := x509.CreateCertificate(rand.Reader,&template, &template, &key.PublicKey, key)
if err != nil {
    log.Fatalf("Failed to create certificate: %v", err)
}
    return derBytes
}


func main() {

    eccKey := GenerateSM2Key()
    certBytes := CreateSelfSignedSM2Certificate(eccKey)

    // 写出PEM编码的X509证书
    pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
    ioutil.WriteFile("sm2.crt", pemBytes, 0644)

    dmcert,_ := x509.ParseCertificate(certBytes)
    //写出不带签名结构的X509证书待签名数据
    ioutil.WriteFile("sm2NoSign.crt", dmcert.RawTBSCertificate, 0644)

    if(sm2.Verify(&eccKey.PublicKey,dmcert.RawTBSCertificate,dmcert.Signature,nil) == nil){
        fmt.Println("X509证书自身签名验证成功")        
    }else{
        fmt.Println("X509证书自身签名验证失败")
    }

}
