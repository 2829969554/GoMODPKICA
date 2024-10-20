package main

import (
    "fmt"
    "tjfoc/gmsm/x509"
    "io/ioutil"
    "crypto/rand"
    "encoding/hex"
    "encoding/pem"

)

func main(){
    prikeypem,_ :=ioutil.ReadFile("sm2.pem")
    sm2pri,_ := x509.ReadPrivateKeyFromPem(prikeypem,nil)
    sm2pub := &sm2pri.PublicKey
    mypri :=x509.WritePrivateKeyToHex(sm2pri)
    mypub :=x509.WritePublicKeyToHex(sm2pub)

    certBytespem,_ :=ioutil.ReadFile("sm2.crt")
    certpem, _ := pem.Decode(certBytespem) 
    
    certBytes:= certpem.Bytes
    dmcert,_ := x509.ParseCertificate(certBytes)

    fmt.Println("公钥",mypub)
    fmt.Println("私钥",mypri)

    fmt.Println("现有签名",hex.EncodeToString(dmcert.Signature))

    fmt.Println("待签名数据",hex.EncodeToString(dmcert.RawTBSCertificate)) 
            

    smz,_ := sm2pub.Sm3Digest(dmcert.RawTBSCertificate,nil)
    fmt.Println("待签名数据SM3",hex.EncodeToString(smz)) 
    
    //证书内部签名验证
    if(sm2pub.Verify(dmcert.RawTBSCertificate,dmcert.Signature) == true){
        fmt.Println("证书内部签名验证成功")
    }else{
        fmt.Println("证书内部签名验证失败")
    }

    //证书内部公钥实时签名验证
    timesign,_:= sm2pri.Sign(rand.Reader,dmcert.RawTBSCertificate,nil)
    if(sm2pub.Verify(dmcert.RawTBSCertificate,timesign) == true){
        fmt.Println("证书内部公钥实时签名验证成功",hex.EncodeToString(timesign))
    }else{
        fmt.Println("证书内部公钥实时签名验证失败")
    }
/*
    //WEB签名例子验证
    websign,_ := hex.DecodeString("3046022100e15caa4b942b01336e400594ebc33d1e33f2a29dbb14eac0058d68e8be092320022100d467613bab35cb90a00f146868f479bf4bde884d0a17be75b4c25fbbb151c16e")
    if(sm2pub.Verify(dmcert.RawTBSCertificate,websign) == true){
        fmt.Println("WEB签名例子验证成功")
    }else{
        fmt.Println("WEB签名例子验证失败")
    }
*/
    
}