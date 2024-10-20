package main
/*
创建时间:2024-10-20 13:57
作用: 生成指定 X509 pkix扩展数据 【证书策略】
*/
import (
    "encoding/asn1"
    "encoding/binary"
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
    
    return []byte("ERROR：func GenerateCPSbyte() 参数不足")     
}