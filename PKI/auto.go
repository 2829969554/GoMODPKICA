package main

import (
	"fmt"
	"os"
	"strings"
	"bufio"
	"time"
	"strconv"
	"io/ioutil"
	"bytes"
	"path/filepath"
)
var MODTC string=""
var MODCERTSdir string=""
var MODCERTSsmdir string=""
func main() {


 ex, err := os.Executable()  
 if err != nil {  
 panic(err)  
 }  
//当前执行目录
MODTC= filepath.Dir(ex)  
MODCERTSdir=MODTC+"\\CERTS.txt"
MODCERTSsmdir=MODTC+"\\CERTS.txt.sm"


args := os.Args


if(len(args)==2){
	if(args[1]=="init"){
		fmt.Println("初始化环境完成")
		CERTSbackup()
		os.Exit(0)
	}

}

if(len(args) >=3){
	if(args[1]=="revoke"  && len(args)==3){
	fmt.Println(len(args),args[1],args[2])

		//fmt.Println("吊销证书",args[2],"没有指定原因")
		modrevokecert(args[2],"R","0",getmodtimeNow())
		return
	}

	if(args[1]=="revoke"  && len(args)==4){
	fmt.Println(len(args),args[1],args[2],args[3])

		//fmt.Println("吊销证书",args[2],"指定原因",args[3])
		modrevokecert(args[2],"R",args[3],getmodtimeNow())
		return
	}
}

if(len(args) >=5){

	if(args[1]=="newcert"){
		//fmt.Println("增加证书",args[2],args[3],args[4],args[5],args[6],args[7])
		if(args[6] !="null"){
			_,err:=modtimeToTime(args[6])
			if err != nil {
				modaddcert(args[2],args[3],args[4],args[5],getmodtimeNow(),args[7])
			}else{
				modaddcert(args[2],args[3],args[4],args[5],args[6],args[7])
			}
		}else{
			modaddcert(args[2],args[3],args[4],args[5],getmodtimeNow(),args[7])
		}

		
		os.Exit(0)
	}
}



fmt.Println(args[1],args[2],args[3],args[4],args[5],args[6],args[7])
fmt.Println("错误:无效操作")
os.Exit(0)
}


//MODPKICA系统 修改证书库证书状态 证书序列号 状态 操作原因 MOD证书库内部文本格式时间
func modrevokecert(certid string,certstatus string,certponse string,certtime string){
	
	file, err := os.Open(MODCERTSdir)
	if err != nil {
		fmt.Println("Error CERTS.txt opening file:", err)
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			words:= strings.Split(line, " ")
			if(words[0]==certid){
				
				if(len(words)==6){
					newline:=words[0]+" "+ words[1] + " " + certstatus+ " " + certponse + " " + certtime + " "+ words[5]
					CERTSallData, _ := ioutil.ReadFile(MODCERTSdir)
					replaced := bytes.Replace(CERTSallData, []byte(line), []byte(newline), -1)
					os.WriteFile(MODCERTSdir, replaced, 0644)
					fmt.Println("吊销成功")
					return
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading from file:", err)
	}
 fmt.Println("吊销失败:CERTS.txt证书库不存在此编号")
 return	
}



//MODPKICA系统 日期时间类型 转 MOD证书库内部文本时间格式
func getmodtimeNow() string {
 // 定义时间格式  不用动我
 modlayout :="2006/01/02-15:04:05" 

 return time.Now().Format(modlayout) 


}

//MODPKICA系统 MOD证书库内部 文本时间格式 转日期时间类型 出错返回err
func modtimeToTime(modtimetext string) (time.Time, error){
 // 定义时间格式  不用动我
 modlayout :="2006/01/02-15:04:05" 
 // 使用time.Parse将字符串解析为time.Time类型  /*
 Time1, err := time.Parse(modlayout, modtimetext)  
 if err != nil {  
 	fmt.Println("解析时间错误:使用当前时间增加证书", err)  
 	return time.Time{}, err
 }
 return  Time1,err
}


//MODPKICA系统 初始化环境备份老文件
func CERTSbackup(){
	oldFilename := MODCERTSdir
	newFilename := MODCERTSdir+".old."+strconv.FormatInt(time.Now().Unix(),10)  
	// 首先检查文件是否存在
	if _, err := os.Stat(oldFilename); os.IsNotExist(err) {
		echonewcertsfile()
		return
	} else if err != nil {
		fmt.Printf("获取文件CERTS.txt状态错误： %v\n", err)
		return
	}
	// 重命名文件
	if err := os.Rename(oldFilename, newFilename); err != nil {
		fmt.Printf("重命名文件CERTS.txt失败： %v\n", err)
		return
	}
	echonewcertsfile()
}


//MODPKICA系统 写出证书列表模板 CERTS.txt.sm
func echonewcertsfile(){
	// 证书表模板文件路径
	filePath := MODCERTSsmdir
	// 读取文件内容
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		// 处理错误 写出
		fileData=[]byte{0x23,0xE5,0xBA,0x8F,0xE5,0x88,0x97,0xE5,0x8F,0xB7,0x20,0x20,0x20,0x20,0xE7,0xB1,0xBB,0xE5,0x9E,0x8B,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0xE7,0x8A,0xB6,0xE6,0x80,0x81,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0xE7,0x8A,0xB6,0xE6,0x80,0x81,0xE5,0x8E,0x9F,0xE5,0x9B,0xA0,0xE7,0xBC,0x96,0xE5,0x8F,0xB7,0x20,0x20,0x20,0xE7,0xAD,0xBE,0xE5,0x8F,0x91,0xE6,0x97,0xB6,0xE9,0x97,0xB4,0x2F,0xE5,0x90,0x8A,0xE9,0x94,0x80,0xE6,0x97,0xB6,0xE9,0x97,0xB4,0x0D,0x0A,0x23,0x20,0x20,0x20,0x20,0x20,0x52,0x4F,0x4F,0x54,0x2F,0x43,0x41,0x2F,0x45,0x4E,0x44,0x20,0x20,0x20,0x56,0xE6,0xAD,0xA3,0xE5,0xB8,0xB8,0x52,0xE5,0x90,0x8A,0xE9,0x94,0x80,0x4E,0xE6,0x9C,0xAA,0xE7,0x9F,0xA5,0x20,0x20,0x20,0x20,0x20,0x30,0x2D,0x39,0x20,0x20,0x20,0x20,0xE4,0xBE,0x8B,0xE5,0xA6,0x82,0x20,0x32,0x30,0x30,0x30,0x2F,0x30,0x36,0x2F,0x31,0x37,0x2D,0x31,0x32,0x3A,0x31,0x32,0x3A,0x31,0x32,0x0D,0x0A}

	}

	// 写入文件
	if err := os.WriteFile(MODCERTSdir, fileData, 0644); err != nil {
		// 处理错误
		fmt.Println("写出文件CERTS.txt出错：", err)
		return
	}
		// 写入文件
	if err := os.WriteFile(MODCERTSsmdir, fileData, 0644); err != nil {
		// 处理错误
		fmt.Println("写出模板文件CERTS.txt.sm出错：", err)
		return
	}
}



//MODPKICA系统 添加证书
func modaddcert(certid string,certtype string,certstatus string,certponse string,certtime string,downcid string){
	newline:=certid+" "+ certtype + " " + certstatus+ " " + certponse + " " + certtime + " "+ downcid + "\r\n"
	// 要追加的内容  
    data := []byte(newline)  
  
    // 以追加模式打开文件，如果文件不存在则创建文件  
    f, err := os.OpenFile(MODCERTSdir, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)  
    if err != nil {  
        fmt.Println(err)  
    }  
    defer f.Close()  
  
    // 将内容写入文件  
    _, err = f.Write(data)  
    if err != nil {  
        fmt.Println(err)
    } 
    fmt.Println("加入证书成功") 
}