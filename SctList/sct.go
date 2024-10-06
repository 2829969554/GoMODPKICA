package main
import(
	"fmt"
	"encoding/hex"
	"strconv"
)

// SCT 代表一个 Signed Certificate Timestamp 的结构
type SCT struct {
	Raw	   	  []byte    //SCT结构体对应字节集
	SCTlenth  int       //当前子SCT长度
    Version   int       // SCT 版本  V1:0
    LogID     []byte    // 日志 ID  字节集长度32，字符串长度64
    Timestamp uint64 // 时间戳 13位数 精确到毫秒
    Hash int  //0:none 1:MD5  2:SHA1 3:SHA224 4:SHA256 5:SHA384 6:SHA512
    Signtype int //0:anonymous 1:RSA  2：DSA  3:ECDSA
    Signature []byte    // SCT 签名 ECDSA签名长度70，字符串长度140
}
//根据参数生成SCT字节集 
//成功:status 返回true data:Raw
//失败 status 返回false data：{0}
func (thisSCT *SCT) CreateSCT()(status bool,data []byte){
	var mybyte []byte
	longer:= 0
	longer += len(thisSCT.Signature) +1  //签名70 + 00 1 
	//longer += len(thisSCT.Signtype) + len(thisSCT.Hash) +1
	longer += 1 + 1 +1+1 //算法长度 1 + 类型长度 1 + 00 1  + 00 1 
	hexstr,_:= hex.DecodeString("0" + strconv.FormatUint(thisSCT.Timestamp, 16))
	longer += len(hexstr) +1+1  //时间戳13  + 00 1 + 00 1 
	longer += len(thisSCT.LogID) 
	longer += 1 //版本号长度
	//longer += 1 //SCT长度  0首位是SCT长度不算，预留
	mybyte = append(mybyte,byte(longer)) //追加长度
	mybyte = append(mybyte,0x00) 	//追加版本号
	mybyte = append(mybyte,(thisSCT.LogID)...)	//追加logid
	mybyte = append(mybyte,0x00) 	//追加 00
	mybyte = append(mybyte,0x00) 	//追加 00
	mybyte = append(mybyte,hexstr...) 	//追加 时间戳
	mybyte = append(mybyte,0x00) 	//追加 00
	mybyte = append(mybyte,0x00) 	//追加 00
	mybyte = append(mybyte,byte(thisSCT.Hash)) 	//追加哈希方法
	mybyte = append(mybyte,byte(thisSCT.Signtype)) 	//追加签名方法
	mybyte = append(mybyte,0x00) 	//追加 00
	mybyte = append(mybyte,(thisSCT.Signature)...)	//追加Signature
	if(len(mybyte)-1== longer){  //这里-1是因为0首位是SCT长度，已经提前预留
		thisSCT.Raw = mybyte
		return true,mybyte
	}
	return false,[]byte{0}
}

//解析单独子SCT
func (thisSCT *SCT) Parse(sct []byte) (err bool){
	parts := SplitWithDelimiter(sct, 0x00)
	//fmt.Println(len(parts))
	//SCT V1  长度有两种 13或者15 13的签名是合成在一起，15的分两段用00间隔
	if(len(parts)==13 || len(parts)==15 || len(parts)==17){
		thisSCT.Raw= sct
		thisSCT.SCTlenth= int(parts[0][0])
		thisSCT.Version= int(parts[1][0]) 
		thisSCT.LogID= parts[2]
		
		timestamp, err := strconv.ParseUint(hex.EncodeToString(parts[6]), 16, 64)
		if err != nil {
			fmt.Println("错误",err,hex.EncodeToString(parts[6]))
		}
	
		thisSCT.Timestamp= timestamp
		thisSCT.Hash= int(parts[10][0])
		thisSCT.Signtype= int(parts[10][1])
		thisSCT.Signature= parts[12]
		//如果是15就将两段数据合成一起
		if(len(parts)==15){
			thisSCT.Signature = append(thisSCT.Signature,parts[13]...)
			thisSCT.Signature = append(thisSCT.Signature,parts[14]...)
		}
		if(len(parts)==17){
			thisSCT.Signature = append(thisSCT.Signature,parts[13]...)
			thisSCT.Signature = append(thisSCT.Signature,parts[14]...)
			thisSCT.Signature = append(thisSCT.Signature,parts[15]...)
			thisSCT.Signature = append(thisSCT.Signature,parts[16]...)
		}
		return true
	}
	return false
}

//时间戳列表，一般包含3组数据，目前不支持2组数据解析
type SCTList struct{
	Raw			   []byte	//SCTList结构体对应字节集
	SCTListlenth   int 		//当前SCTList总长度
	SCTs		   []SCT 	//SCT数组
}
//根据现有SCT生成符合条件的SCT列表
func (thisSCT *SCTList) CreateSCTList()(status bool,data []byte){
	var mybyte,mybyte2,mybyte3 []byte
	langer := 0
	for _, sct := range thisSCT.SCTs {
		a,b := sct.CreateSCT()
		langer += len(b)
		if(a == false){
			fmt.Println("出错了 CreateSCTList函数中 sct.CreateSCT()")
			return false,[]byte{0}
		}
		mybyte = append(mybyte,0x00)
		mybyte = append(mybyte,b...)
	}

	mybyte2 = append(mybyte2,0x00)
	langer += 1
	mybyte2 = append(mybyte2,byte(langer))
	mybyte2 = append(mybyte2,mybyte...)
	langer += 1
	mybyte3 = append(mybyte3,0x04)
	mybyte3 = append(mybyte3,0x82)
	mybyte3 = append(mybyte3,0x00)
	langer += 1
	mybyte3 = append(mybyte3,byte(langer))
	mybyte3 = append(mybyte3,mybyte2...)

	//fmt.Println(hex.EncodeToString(mybyte3),len(mybyte3),langer)
	if(len(mybyte3)-4 == langer){  //这里-4是因为 0x04 0x82 0x00 0xlanger 头部预留4位置
		thisSCT.Raw = mybyte3
		return true,mybyte3
	}
	return false,[]byte{0}
}
//解析SCT列表 签名证书列表
func (thisSCTlist *SCTList) Parse (mysctlist []byte)(err bool){
	thisSCTlist.Raw= mysctlist
	rows := SplitWithDelimiter(mysctlist,0x00)
	/*for _, part := range rows {
		fmt.Println("Part:", hex.EncodeToString(part))
	}
	*/
	//fmt.Println(len(rows))
	if(len(rows)>0){
		lenth, err := strconv.ParseInt(hex.EncodeToString(rows[0]), 16,0)
		if err != nil {
			fmt.Println("错误",err,hex.EncodeToString(rows[0]))
		}
		thisSCTlist.Raw= mysctlist
		thisSCTlist.SCTListlenth= int(lenth)
		//fmt.Println("len:", len(rows),lenth)
		//2 16 32
		var fori,index int //3组
		fori = int(lenth / 117)
		SCTstmp:= make([]SCT, fori)
		//fmt.Println("数量:", len(SCTstmp))
		index=	int(rows[2][0])
		next:= 3
		next2:= index+4

		next3:= 0
		for i := 0; i < fori; i++ {
			//3-117,118-1
			//fmt.Println(hex.EncodeToString(mysctlist[next:next2]))
			SCTstmp[i].Parse(mysctlist[next:next2])

			if(i == fori-1){
				break
			}
			next3= int(mysctlist[next2+1 :next2+2][0])
			next = next + next3+(i+1)
			index = index + next3
			next2= index+4+2*(i+1)

		}
		thisSCTlist.SCTs = SCTstmp
		return true
	}

	return false
}

// SplitWithDelimiter 分割字节切片，包含分隔符
func SplitWithDelimiter(b []byte, delimiter byte) [][]byte {
	var parts [][]byte
	var start int

	for i, v := range b {
		if v == delimiter {
			parts = append(parts, b[start:i])
			start = i + 1
			// 添加分隔符
			parts = append(parts, []byte{delimiter})
		}
	}

	// 添加最后一个部分
	if start < len(b) {
		parts = append(parts, b[start:])
	}

	return parts
}
/*
func main(){

	mysct := []byte{0x75,0x00,0x12,0xF1,0x4E,0x34,0xBD,0x53,0x72,0x4C,0x84,0x06,0x19,0xC3,0x8F,0x3F,0x7A,0x13,0xF8,0xE7,0xB5,0x62,0x87,0x88,0x9C,0x6D,0x30,0x05,0x84,0xEB,0xE5,0x86,0x26,0x3A,0x00,0x00,0x01,0x91,0x44,0xA4,0xE4,0x5E,0x00,0x00,0x04,0x03,0x00,0x46,0x30,0x44,0x02,0x20,0x42,0xEE,0x56,0xF3,0x66,0x3B,0x32,0xA6,0xDD,0xF1,0x50,0x47,0x81,0xC2,0xF2,0x17,0x80,0x3D,0x5C,0x12,0x13,0x2F,0x4A,0x99,0x3F,0xE5,0x5F,0x86,0x29,0xDC,0xDD,0x59,0x02,0x20,0x70,0x47,0xE0,0x87,0xFA,0xA3,0xA6,0x11,0xBB,0x8D,0x0D,0xE1,0x98,0xCC,0xFA,0x01,0xB2,0x65,0xDC,0x0F,0x6C,0x7C,0x63,0x92,0xD8,0x48,0xAD,0x32,0xFD,0x4E,0xCB,0x1E}
	var thisSCT SCT
	
	fmt.Println("单独子SCT解析状态",thisSCT.Parse(mysct))
	fmt.Println(fmt.Sprintf("\n子SCT长度：%d\nLOG版本号(0: V1):%d\nLogID：%X\n时间戳:%d\n哈希算法(SHA256):%d\n签名算法(ECDSA):%d\n签名：%x\n",thisSCT.SCTlenth,thisSCT.Version,thisSCT.LogID,thisSCT.Timestamp,thisSCT.Hash,thisSCT.Signtype,thisSCT.Signature))
	fmt.Println("\n")


	//0x04,0x82,0x01,0x69,  SCT数据头 目前需要单独往前面追加计算 
	//0x82代表总长度大于255，超长asn1.value三组SCT的总长度
	//0x81代表总长度大于127  一般指 长asn1.value,2组SCT的长度
	//例子1 此列表包含3组SCT
	mysctlist1 :=[]byte{0x01,0x67,0x00,0x75,0x00,0x12,0xF1,0x4E,0x34,0xBD,0x53,0x72,0x4C,0x84,0x06,0x19,0xC3,0x8F,0x3F,0x7A,0x13,0xF8,0xE7,0xB5,0x62,0x87,0x88,0x9C,0x6D,0x30,0x05,0x84,0xEB,0xE5,0x86,0x26,0x3A,0x00,0x00,0x01,0x91,0x44,0xA4,0xE4,0x5E,0x00,0x00,0x04,0x03,0x00,0x46,0x30,0x44,0x02,0x20,0x42,0xEE,0x56,0xF3,0x66,0x3B,0x32,0xA6,0xDD,0xF1,0x50,0x47,0x81,0xC2,0xF2,0x17,0x80,0x3D,0x5C,0x12,0x13,0x2F,0x4A,0x99,0x3F,0xE5,0x5F,0x86,0x29,0xDC,0xDD,0x59,0x02,0x20,0x70,0x47,0xE0,0x87,0xFA,0xA3,0xA6,0x11,0xBB,0x8D,0x0D,0xE1,0x98,0xCC,0xFA,0x01,0xB2,0x65,0xDC,0x0F,0x6C,0x7C,0x63,0x92,0xD8,0x48,0xAD,0x32,0xFD,0x4E,0xCB,0x1E,0x00,0x76,0x00,0xE6,0xD2,0x31,0x63,0x40,0x77,0x8C,0xC1,0x10,0x41,0x06,0xD7,0x71,0xB9,0xCE,0xC1,0xD2,0x40,0xF6,0x96,0x84,0x86,0xFB,0xBA,0x87,0x32,0x1D,0xFD,0x1E,0x37,0x8E,0x50,0x00,0x00,0x01,0x91,0x44,0xA4,0xE4,0x66,0x00,0x00,0x04,0x03,0x00,0x47,0x30,0x45,0x02,0x20,0x44,0xAA,0x14,0x26,0x63,0x6F,0x27,0x30,0xBD,0x59,0x7F,0xB0,0x65,0xDB,0xBA,0x1E,0x63,0xCE,0x35,0x02,0x5E,0x50,0x4C,0x85,0xBA,0x15,0x56,0x12,0xCA,0x15,0x8B,0xB3,0x02,0x21,0x00,0xEC,0x76,0xF8,0xB0,0x89,0x2C,0x8F,0xF4,0x59,0xCE,0xA0,0x79,0xEE,0x3A,0xFF,0xBA,0xB0,0x1C,0x47,0x0F,0x21,0xD2,0x28,0xB1,0x8F,0xD5,0x6F,0x53,0x85,0xAA,0xDF,0x7A,0x00,0x76,0x00,0xCC,0xFB,0x0F,0x6A,0x85,0x71,0x09,0x65,0xFE,0x95,0x9B,0x53,0xCE,0xE9,0xB2,0x7C,0x22,0xE9,0x85,0x5C,0x0D,0x97,0x8D,0xB6,0xA9,0x7E,0x54,0xC0,0xFE,0x4C,0x0D,0xB0,0x00,0x00,0x01,0x91,0x44,0xA4,0xE4,0x66,0x00,0x00,0x04,0x03,0x00,0x47,0x30,0x45,0x02,0x20,0x7A,0x35,0xA5,0xF3,0xB9,0x84,0xC9,0xF6,0xCD,0x2D,0xAE,0x7D,0x01,0x05,0x7A,0x45,0x04,0x2A,0x10,0x33,0x5A,0x39,0xD4,0xDC,0x10,0x81,0xC3,0x6B,0xC0,0x18,0x4D,0xA3,0x02,0x21,0x00,0x90,0x5F,0x9B,0xB6,0x79,0x2C,0x86,0xD9,0x1F,0x34,0xAE,0xA7,0x3C,0x29,0xEE,0xB2,0x85,0xFA,0x71,0x26,0xAB,0x97,0x36,0x28,0x93,0x80,0xE0,0xCD,0x6D,0x4F,0xA1,0x0C}
	//例子2 此列表包含3组SCT
	mysctlist2 :=[]byte{0x01,0x67,0x00,0x75,0x00,0x3F,0x17,0x4B,0x4F,0xD7,0x22,0x47,0x58,0x94,0x1D,0x65,0x1C,0x84,0xBE,0x0D,0x12,0xED,0x90,0x37,0x7F,0x1F,0x85,0x6A,0xEB,0xC1,0xBF,0x28,0x85,0xEC,0xF8,0x64,0x6E,0x00,0x00,0x01,0x8B,0xD2,0x12,0xE5,0xD0,0x00,0x00,0x04,0x03,0x00,0x46,0x30,0x44,0x02,0x20,0x14,0x5C,0xDE,0x40,0xFC,0x54,0x35,0x46,0x53,0x73,0xB8,0x99,0xF5,0x4A,0xD7,0x9D,0xD8,0x37,0x37,0x8C,0x60,0x40,0x7B,0x99,0x35,0x01,0xE8,0xAC,0x31,0xE3,0x50,0x98,0x02,0x20,0x31,0x4E,0x87,0x6A,0xD5,0xE9,0x98,0xC5,0x8D,0xFA,0x39,0x6D,0xB1,0x45,0x86,0x0E,0xE2,0xDA,0xFC,0x34,0xAC,0xB8,0xFD,0xB9,0x59,0xB0,0x5A,0x34,0x24,0x5B,0xA4,0xBF,0x00,0x76,0x00,0xEE,0xCD,0xD0,0x64,0xD5,0xDB,0x1A,0xCE,0xC5,0x5C,0xB7,0x9D,0xB4,0xCD,0x13,0xA2,0x32,0x87,0x46,0x7C,0xBC,0xEC,0xDE,0xC3,0x51,0x48,0x59,0x46,0x71,0x1F,0xB5,0x9B,0x00,0x00,0x01,0x8B,0xD2,0x12,0xE5,0xA5,0x00,0x00,0x04,0x03,0x00,0x47,0x30,0x45,0x02,0x21,0x00,0xFD,0xC5,0x2B,0x47,0xC5,0xBA,0xD0,0x96,0x0C,0x11,0xBF,0xF5,0xC2,0x65,0x85,0xE2,0x9A,0x9A,0x2C,0xC1,0x0C,0x5A,0xAF,0xF3,0x33,0x74,0xD3,0xC9,0x4E,0xD0,0x1B,0x11,0x02,0x20,0x0A,0x46,0x46,0xCE,0x01,0x71,0xAE,0xC1,0xA8,0x84,0x75,0x7A,0x9E,0xA3,0x32,0x85,0xF4,0x75,0x84,0x57,0x9B,0x90,0x80,0x66,0x35,0x6F,0x0F,0x88,0x4C,0xA8,0x34,0xB3,0x00,0x76,0x00,0x48,0xB0,0xE3,0x6B,0xDA,0xA6,0x47,0x34,0x0F,0xE5,0x6A,0x02,0xFA,0x9D,0x30,0xEB,0x1C,0x52,0x01,0xCB,0x56,0xDD,0x2C,0x81,0xD9,0xBB,0xBF,0xAB,0x39,0xD8,0x84,0x73,0x00,0x00,0x01,0x8B,0xD2,0x12,0xE5,0xC1,0x00,0x00,0x04,0x03,0x00,0x47,0x30,0x45,0x02,0x20,0x05,0xE6,0xFE,0xEA,0xEE,0xCD,0xAA,0x4E,0x3D,0x08,0x5C,0x5A,0x50,0x4D,0x00,0x42,0x4F,0x65,0x59,0xB2,0x92,0xDA,0x86,0x2E,0xD6,0x7F,0xB4,0xD8,0x55,0x2F,0x93,0x4D,0x02,0x21,0x00,0xF7,0x98,0x79,0x55,0x84,0x90,0x7B,0xDB,0xBE,0xA0,0x5D,0xB8,0x35,0xAB,0xF2,0x7A,0x41,0x81,0x7D,0x60,0x50,0xB2,0x55,0x96,0x62,0x9D,0x08,0x7B,0x51,0x5D,0xC0,0x24}
	//例子3 此列表包含2组SCT，目前无法识别
	//mysctlist3 :=[]byte{0x00,0xF1,0x00,0x76,0x00,0xDA,0xB6,0xBF,0x6B,0x3F,0xB5,0xB6,0x22,0x9F,0x9B,0xC2,0xBB,0x5C,0x6B,0xE8,0x70,0x91,0x71,0x6C,0xBB,0x51,0x84,0x85,0x34,0xBD,0xA4,0x3D,0x30,0x48,0xD7,0xFB,0xAB,0x00,0x00,0x01,0x91,0xB8,0x46,0xC9,0x5E,0x00,0x00,0x04,0x03,0x00,0x47,0x30,0x45,0x02,0x20,0x00,0xA7,0xE2,0x7F,0x41,0xFA,0xB5,0xD8,0x69,0x72,0xD4,0xA2,0x4E,0xE9,0x12,0xB6,0x80,0xFD,0x26,0x66,0xF3,0x00,0x01,0xD3,0xF7,0xCF,0x81,0xC4,0xF6,0x66,0x18,0xCA,0x02,0x21,0x00,0x9B,0xD6,0x19,0x00,0xA0,0xEB,0x67,0x33,0xED,0x5E,0x83,0xCA,0xA7,0xA9,0xFF,0xF7,0xA8,0x5C,0x56,0x2C,0x73,0xE2,0xE0,0x66,0x39,0x60,0xC3,0x57,0x08,0xDA,0xD6,0xC4,0x00,0x77,0x00,0xEE,0xCD,0xD0,0x64,0xD5,0xDB,0x1A,0xCE,0xC5,0x5C,0xB7,0x9D,0xB4,0xCD,0x13,0xA2,0x32,0x87,0x46,0x7C,0xBC,0xEC,0xDE,0xC3,0x51,0x48,0x59,0x46,0x71,0x1F,0xB5,0x9B,0x00,0x00,0x01,0x91,0xB8,0x46,0xC5,0x2E,0x00,0x00,0x04,0x03,0x00,0x48,0x30,0x46,0x02,0x21,0x00,0x8B,0x5A,0x84,0x70,0xAA,0xDC,0xD1,0xBB,0x4E,0x21,0xE3,0xE2,0x56,0x44,0xB9,0x94,0x14,0xFD,0x68,0xF7,0x16,0xE4,0x98,0xFB,0xB4,0x26,0xF7,0xB8,0x36,0xB9,0xCB,0x20,0x02,0x21,0x00,0xED,0xE0,0xA6,0xE8,0xA1,0x36,0xBE,0x2C,0xE5,0xFB,0xF0,0x11,0x6E,0x78,0xC8,0x02,0x30,0xAB,0x15,0xB7,0xFD,0xE9,0x0B,0x1B,0xFF,0x1D,0x5E,0xD6,0x6E,0xF8,0xC0,0x1E}
	fmt.Println("\n")
	var thisSCTlist SCTList
	fmt.Println("例子1 解析状态",thisSCTlist.Parse(mysctlist1))
	fmt.Println("例子1 SCTs数据",)
	for i, sct := range thisSCTlist.SCTs {
		fmt.Println(fmt.Sprintf("第%d组SCT\nSCT长度：%d\nLOG版本号(0: V1):%d\nLogID：%X\n时间戳:%d\n哈希算法(SHA256):%d\n签名算法(ECDSA):%d\n签名：%x\n",i,sct.SCTlenth,sct.Version,sct.LogID,sct.Timestamp,sct.Hash,sct.Signtype,sct.Signature))
	}
	fmt.Println("\n")
	fmt.Println("例子2 解析状态",thisSCTlist.Parse(mysctlist2))
	fmt.Println("例子2 SCTs数据")
	for i, sct := range thisSCTlist.SCTs {
		fmt.Println(fmt.Sprintf("第%d组SCT\nSCT长度：%d\nLOG版本号(0: V1):%d\nLogID：%X\n时间戳:%d\n哈希算法(SHA256):%d\n签名算法(ECDSA):%d\n签名：%x\n",i,sct.SCTlenth,sct.Version,sct.LogID,sct.Timestamp,sct.Hash,sct.Signtype,sct.Signature))
	}
}
*/