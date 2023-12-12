package main

import(
"fmt"
"os"
"path/filepath"
"bufio" 
"os/exec"
"strings" 
)
func rtrim(s string) string {  
 for len(s) > 0 && s[len(s)-1] == ',' {  
 s = s[:len(s)-1]  
 }  
 return s  
} 

func main() {
MODML:=os.Args
 ex, err := os.Executable()  
 if err != nil {  
 panic(err)  
 }  

//当前执行目录
MODTC:= filepath.Dir(ex)  
//编辑文件
MODAUTOEXE:=MODTC+"\\PKI\\auto.exe"

//签发吊销列表执行程序
MODrootGETcrlEXE:=MODTC+"\\rootGETcrl.exe"

//所有证书记录表
MODPKI_certsfile:=MODTC+"\\PKI\\CERTS.txt"

//特定目录
MODPKI_rootdir:=MODTC+"\\PKI\\ROOT\\"
MODPKI_cadir:=MODTC+"\\PKI\\CA\\"
MODPKI_certdir:=MODTC+"\\PKI\\CERT\\"
MODPKI_keydir:=MODTC+"\\PKI\\KEY\\"

MODPKI_WEBdir:=MODTC+"\\PKI\\WebPublic\\"
MODPKI_WEBcrtdir:=MODTC+"\\PKI\\WebPublic\\CRT\\"
MODPKI_WEBcrldir:=MODTC+"\\PKI\\WebPublic\\CRL\\"
if(1==2){
	fmt.Println(MODTC,MODPKI_certsfile,MODPKI_rootdir,MODPKI_cadir,MODPKI_certdir,MODPKI_keydir,MODPKI_WEBdir,MODPKI_WEBcrtdir,MODPKI_WEBcrldir)

}

 




if(len(MODML)==1){
	fmt.Println("***************MOD-PKI-CA系统功能列表****************")
	fmt.Println("init ------------------------------------初始化环境签发根证书ROOT")
	fmt.Println("                     （执行本操作后将自动化自动执行initOCSP和initTIMSTAMP）")
	fmt.Println("")
	fmt.Println("initOCSP --------------------------------初始化OCSP签名专用证书")
	fmt.Println("initTIMSTAMP ----------------------------初始化TSA时间戳签名专用证书")
	fmt.Println("            （人工操作，可空参数SHA1 或 SHA256）指定算法更新，默认两者同时更新")
	fmt.Println("")
	fmt.Println("list ------------------------------------查看所有证书")
	fmt.Println("signCERT --------------------------------签发证书")
	fmt.Println("RevokeCERT ------------------------------吊销证书")
	fmt.Println("signCRL ---------------------------------签发吊销列表")
	fmt.Println("verifyCERT ------------------------------验证证书")
	fmt.Println("VERSION ---------------------------------查看版本号")
	fmt.Println("*****************************************************")
	os.Exit(0)
}

//fmt.Println("命令行参数数量:",len(MODML))

if(MODML[1]=="init"){
	fmt.Println("初始化新的根证书环境")
	fmt.Println("输入参数后请按回车键，如留空可直接按回车")
	question := []string{
		"请输入证书公共名称(CN): ",
		"请输入组织名称(O): ",
		"请输入部门名称(OU): ",
		"请输入国家名称(C) 例如CN、US:",
		"请输入省级地区名称(S):",
		"请输入市级城市名称(L):",
		"请输入街道名称(STREET):",
		"请输入地区邮政编码(PostalCode):",
		"请输入任意身份标识码(SERIALNUMBER):",
	}
	questionid := []string{"CN", "O", "OU", "C", "S", "L", "STREET", "PostalCode", "SERIALNUMBER"}

 scanner := bufio.NewScanner(os.Stdin)  
 var inputs []string  
  
 for i := 0; i < 9; i++ {  
	 fmt.Print(question[i])  
	 scanner.Scan()  
	 input := scanner.Text()  
	 inputs = append(inputs, questionid[i]+"="+input)  
 }  
  
 var finalString string  

 for _, input := range inputs {  
 	 //空格把改为%
	 input=strings.Replace(input, " ", "%", -1)
	 finalString += input + ","
 }  
 lastCommaIndex:= strings.LastIndex(finalString, ",")
 finalString    = finalString[:lastCommaIndex]
 //fmt.Println(finalString) 

	keybit:=""
	hash:="sha1"
	fmt.Print("请输入密钥位数（1024-2048-4096-8192）：")
	fmt.Scanln(&keybit) 
	fmt.Print("请输入哈希算法（sha1,sha256,sha384,sha512,SHA256RSAPSS,SHA384RSAPSS,SHA512RSAPSS）：")
	fmt.Scanln(&hash) 
	//fmt.Println(subname,keybit,hash)
	
	 // 命令行参数  
	 var args []string
	 args=[]string{finalString,keybit,hash} 
	 // 创建一个*Cmd对象，表示要执行的命令  
	 cmd := exec.Command(MODTC+"\\MAKEROOT.EXE", args...)  
	  
	 // 运行命令并等待它完成  
	 output, err := cmd.CombinedOutput()  
	 if err != nil {  
		 fmt.Println("命令执行出错:", err)  
	 }  
	 // 打印命令的输出结果  
	 fmt.Println(string(output)) 

	 args=[]string{"initOCSP"}
	 cmd = exec.Command(MODTC+"\\ADMIN.EXE", args...)  
	 // 运行命令并等待它完成  
	 output, err = cmd.CombinedOutput()  
	 if err != nil {  
		 fmt.Println("命令执行出错:", err)  
	 }  
	 // 打印命令的输出结果  
	 fmt.Println(string(output))

	 args=[]string{"initTIMSTAMP"}
	 cmd = exec.Command(MODTC+"\\ADMIN.EXE", args...)  
	 // 运行命令并等待它完成  
	 output, err = cmd.CombinedOutput()  
	 if err != nil {  
		 fmt.Println("命令执行出错:", err)  
	 }  
	 // 打印命令的输出结果  
	 fmt.Println(string(output))

	os.Exit(0)
}
if(MODML[1]=="list" || MODML[1]=="LIST" || MODML[1]=="ls" || MODML[1]=="LS"){
	fmt.Println("查看当前所有证书数量和信息")
    // 打开文件  
    file, err := os.Open(MODPKI_certsfile)  
    if err != nil {  
        fmt.Println(err)  
        return  
    }  
    defer file.Close()  
  
    // 创建一个新的 Reader  
    reader := bufio.NewReader(file)  
  	fileindex:=0
    // 循环读取每一行  
    for{  
        line, err := reader.ReadString('\n')  
        if err != nil {  
            break 
        } 
        if(line[0]=='#'){
        	continue
        }else{
        	fileindex=fileindex+1
        } 
        fmt.Println(line) // 输出这一行  
    } 
    fmt.Println("统计总数量：",fileindex)
	os.Exit(0)
}
if(MODML[1]=="signCERT"){
	fmt.Println("签发下级用户证书")
    fmt.Println("输入参数后请按回车键，如留空可直接按回车")
	question := []string{
		"请输入证书公共名称(CN): ",
		"请输入组织名称(O): ",
		"请输入部门名称(OU): ",
		"请输入国家名称(C) 例如CN、US:",
		"请输入省级地区名称(S):",
		"请输入市级城市名称(L):",
		"请输入街道名称(STREET):",
		"请输入地区邮政编码(PostalCode):",
		"请输入任意身份标识码(SERIALNUMBER):",
		"邮箱号码(EMAIL):",
		"EV扩展验证证书 注册国家(EVCT):",
		"EV扩展验证证书 注册地区(EVCITY):",
		"EV扩展验证证书 注册类型(EVTYPE) 例如Private Organization:",
	}
	questionid := []string{"CN", "O", "OU", "C", "S", "L", "STREET", "PostalCode", "SERIALNUMBER","EMAIL","EVCT","EVCITY","EVTYPE"}

 scanner := bufio.NewScanner(os.Stdin)  
 var inputs []string  
  
 for i := 0; i < 13; i++ {  
	 fmt.Print(question[i])  
	 scanner.Scan()  
	 input := scanner.Text()  
	 inputs = append(inputs, questionid[i]+"="+input)  
 }  
  
 var finalString string  

 for _, input := range inputs {  
 	 //空格把改为%
	 input=strings.Replace(input, " ", "%", -1)
	 finalString += input + ","
 }  
 lastCommaIndex:= strings.LastIndex(finalString, ",")
 finalString    = finalString[:lastCommaIndex]
 //fmt.Println(finalString) 

	keybit:=""
	hash:="sha1"
	fmt.Print("请输入密钥位数（1024-2048-4096-8192）：")
	fmt.Scanln(&keybit) 
	fmt.Print("请输入哈希算法（sha1,sha256,sha384,sha512,SHA256RSAPSS,SHA384RSAPSS,SHA512RSAPSS）：")
	fmt.Scanln(&hash) 
	//fmt.Println(subname,keybit,hash)
	
	 // 命令行参数  
	 var args []string
	 args=[]string{finalString,keybit,hash} 
	 // 创建一个*Cmd对象，表示要执行的命令  
	 cmd := exec.Command(MODTC+"\\MAKECERT.EXE", args...)  
	  
	 // 运行命令并等待它完成  
	 output, err := cmd.CombinedOutput()  
	 if err != nil {  
		 fmt.Println("命令执行出错:", err)  
		 return  
	

	 }  
	 
	 // 打印命令的输出结果  
	 fmt.Println(string(output)) 
	os.Exit(0)
}
if(MODML[1]=="RevokeCERT"){
	fmt.Println("吊销证书")
	if(len(MODML)==2){
		fmt.Println("用法 RevokeCERT 证书编号 吊销原因编号（可空）")
		fmt.Println("例如：ADMIN RevokeCERT A00001")
		fmt.Println("例如：ADMIN RevokeCERT A00002 5")
		fmt.Println("吊销原因编号如下")
		fmt.Println("0:未指定           1:密钥被盗用             2.私钥泄露")
		fmt.Println("3:从属关系已更改   4:被取代(续发、换新)     5.终止服务")
		fmt.Println("6:证书被回收       7:有权机关要求           8.从CRL删除")
		
		return
	}


	 // 命令行参数  
	 var args []string
	 if(len(MODML)==3){
	 	args=[]string{"revoke",MODML[2],"0"}  
	 }
	 if(len(MODML)==4){
	 	args=[]string{"revoke", MODML[2], MODML[3]}  
	 }
	 
	  
	 // 创建一个*Cmd对象，表示要执行的命令  
	 cmd := exec.Command(MODAUTOEXE, args...)  
	  
	 // 运行命令并等待它完成  
	 output, err := cmd.CombinedOutput()  
	 if err != nil {  
		 fmt.Println("命令执行出错:", err)  
		 return  
	 }  
	  
	 // 打印命令的输出结果  
	 fmt.Println(string(output))  


	os.Exit(0)
}
if(MODML[1]=="signCRL"){
	fmt.Println("签发吊销列表")

	 // 创建一个*Cmd对象，表示要执行的命令  
	 cmd := exec.Command(MODrootGETcrlEXE,)  
	  
	 // 运行命令并等待它完成  
	 output, err := cmd.CombinedOutput()  
	 if err != nil {  
		 fmt.Println("命令执行出错:", err,output)  
		 return  
	 } 
	 if(string(output)==""){
	 	fmt.Println("生成成功！") 
	 }else{
	 	fmt.Println(string(output))
	 }
	 
	os.Exit(0)
}




//初始化OCSP专用签名证书
if(MODML[1]=="initOCSP"){
	fmt.Println("初始化新OCSP响应签名证书")
	 // 命令行参数  
	 args:=[]string{"initOCSP"}  
	  
	 // 创建一个*Cmd对象，表示要执行的命令  
	 cmd := exec.Command(MODTC+"\\MAKECERT.EXE", args...) 	  
	 // 运行命令并等待它完成  
	 output, _ := cmd.CombinedOutput()  
	 fmt.Println(string(output),err)
	os.Exit(0)
}

//初始化TIMSTAMP时间戳专用签名证书
if(MODML[1]=="initTIMSTAMP"){
	if(len(MODML)==2){
		 //说明没带参数
		 // 命令行参数  
		 args:=[]string{"initTIMSTAMP","SHA1"}  
		 cmd := exec.Command(MODTC+"\\ADMIN.EXE", args...) 	  
		 // 运行命令并等待它完成  
		 outtext,err:=cmd.CombinedOutput()  
		 if err != nil {
		 	fmt.Println(err)
		 	return 
		 }
		 if(string(outtext)!=""){
		 	fmt.Println(string(outtext))
		 } 

		 args=[]string{"initTIMSTAMP","SHA256"}   
		 cmd = exec.Command(MODTC+"\\ADMIN.EXE", args...) 	  
		 // 运行命令并等待它完成  
		 outtext,err=cmd.CombinedOutput()  
		 if err != nil {
		 	fmt.Println(err)
		 	return 
		 }
		 if(string(outtext)!=""){
		 	fmt.Println(string(outtext))
		 } 
		 
		return
	}

	 if(len(MODML)==3){
		 args:=[]string{"initTIMSTAMP",MODML[2]}  
	  	 fmt.Println("初始化TSA时间戳签名专用",MODML[2],"证书")
		 cmd := exec.Command(MODTC+"\\MAKECERT.EXE", args...) 	  
		 // 运行命令并等待它完成  
		 outtext,err:=cmd.CombinedOutput()  
		 if err != nil {
		 	fmt.Println(err)
		 	return 
		 }
		 if(string(outtext)!=""){
		 	fmt.Println(string(outtext))
		 }

	 }
	os.Exit(0)
}




if(MODML[1]=="verifyCERT"){
	fmt.Println("验证证书链")
	os.Exit(0)
}

if(MODML[1]=="VERSION" || MODML[1]=="version"  || MODML[1]=="ver"  || MODML[1]=="VER"){
	fmt.Println("MOD PKI CA:3.2")
	os.Exit(0)
}











fmt.Println("ERROR:错误,无法处理业务")
fmt.Println("未知参数数量")
for k,v:= range os.Args{
fmt.Printf("args[%v]=[%v]\n",k,v)
}

os.Exit(0)
}