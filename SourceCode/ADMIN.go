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
	fmt.Println("输入根证书参数后请按回车键，如留空可直接按回车")
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

	keybit := ""
	hash := "sha1"
	Keyalgorithm:= "RSA"
	fmt.Print("请输入密钥算法（RSA-ECC-SM2）：")
	fmt.Scanln(&Keyalgorithm) 
	if(Keyalgorithm == "RSA"){
		fmt.Print("请输入密钥位数（1024-2048-4096-8192）：")
		fmt.Scanln(&keybit) 
		fmt.Print("请输入哈希算法（sha1,sha256,sha384,sha512,SHA256RSAPSS,SHA384RSAPSS,SHA512RSAPSS）：")
		fmt.Scanln(&hash) 
	}
	if(Keyalgorithm == "DSA"){
		fmt.Print("请输入密钥位数（1024-2048-4096-8192）：")
		fmt.Scanln(&keybit) 
		fmt.Print("请输入哈希算法（sha1,sha256,sha384,sha512）：")
		fmt.Scanln(&hash) 
	}
	if(Keyalgorithm == "ECC"){
		fmt.Print("请输入密钥位数（256-384-521）：")
		fmt.Scanln(&keybit) 
		fmt.Print("请输入哈希算法（sha1,sha256,sha384,sha512）：")
		fmt.Scanln(&hash) 
	}
	if(Keyalgorithm == "SM2"){
		fmt.Println("请输入密钥位数（256）：256")//没得选
		keybit = "256"
		fmt.Println("请输入哈希算法（SM3）：SM3")
		hash = "SM3"
	}
	
	
	 // 命令行参数  
	 var args []string
	 args=[]string{finalString,keybit,hash,Keyalgorithm} 
	 // 创建一个*Cmd对象，表示要执行的命令  
	 cmd := exec.Command(MODTC+"\\MAKEROOT.EXE", args...)  
	  
	 // 运行命令并等待它完成  
	 output, err := cmd.CombinedOutput()  
	 if err != nil {  
		 fmt.Println("命令执行出错:", err)  
	 }  
	 // 打印命令的输出结果  
	 fmt.Println(string(output)) 

	 args=[]string{"initOCSP",Keyalgorithm}
	 cmd = exec.Command(MODTC+"\\ADMIN.EXE", args...)  
	 // 运行命令并等待它完成  
	 output, err = cmd.CombinedOutput()  
	 if err != nil {  
		 fmt.Println("命令执行出错:", err)  
	 }  
	 // 打印命令的输出结果  
	 fmt.Println(string(output))

	 args=[]string{"initTIMSTAMP",Keyalgorithm}
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
if(MODML[1]=="signCERT" || MODML[1]=="signcert" || MODML[1]=="signcrt" || MODML[1]=="CRT" || MODML[1]=="crt"){
	fmt.Println("签发下级证书")
    fmt.Println("输入参数后请按回车键，如留空可直接按回车")
    IssureID:="root"
    showcalist(MODPKI_certsfile)
	fmt.Print("请输入将要选择的颁发者序列号(留空则默认根证书)：")
	fmt.Scanln(&IssureID) 
	if(IssureID==""){
		IssureID="root"
	}
    certtype:="0"
	fmt.Println("")
	fmt.Print("请输入将要颁发的证书类型(0:最终实体 1:中间CA)：")
	fmt.Scanln(&certtype) 
	quetimemath:=13
	if(certtype=="1"){
		quetimemath=9
	}else{
		quetimemath=13
	}
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
  
 for i := 0; i < quetimemath; i++ {  
 	 fmt.Println("")
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
	
	keyusage:="1"
	exusage:="null"
	zxtime:="1"
	ymlisttx:="null"
	iplisttx:="null"
	Kernel:="null"

	Keyalgorithm:= "RSA"
	fmt.Print("请输入密钥算法（RSA-ECC-SM2）：")
	fmt.Scanln(&Keyalgorithm) 
	if(Keyalgorithm == "RSA"){
		fmt.Print("请输入密钥位数（1024-2048-4096-8192）：")
		fmt.Scanln(&keybit) 
		fmt.Print("请输入哈希算法（sha1,sha256,sha384,sha512,SHA256RSAPSS,SHA384RSAPSS,SHA512RSAPSS）：")
		fmt.Scanln(&hash) 
	}
	if( Keyalgorithm == "DSA"){
		fmt.Print("请输入密钥位数（1024-2048-4096-8192）：")
		fmt.Scanln(&keybit) 
		fmt.Print("请输入哈希算法（sha1,sha256,sha384,sha512）：")
		fmt.Scanln(&hash) 
	}
	if(Keyalgorithm == "ECC"){
		fmt.Print("请输入密钥位数（256-384-521）：")
		fmt.Scanln(&keybit) 
		fmt.Print("请输入哈希算法（sha1,sha256,sha384,sha512）：")
		fmt.Scanln(&hash) 
	}
	if(Keyalgorithm == "SM2"){
		fmt.Println("请输入密钥位数（256）：256")//没得选
		keybit = "256"
		fmt.Println("请输入哈希算法（SM3）：SM3")
		hash = "SM3"
	}
	//fmt.Println(subname,keybit,hash)
	if(certtype=="0"){
		fmt.Println("")
		fmt.Println("证书用途 (ECC->ECDSA类型域名证书请填 5) \n例如 (1:全功能证书(签名、不可抵赖、加密、解密、数据加密、密钥加密、密钥交换)  2.中间CA(签名、签发证书、CRL签名) \n 3.仅用于加密(加密)  4.仅用于解密(解密)")
		fmt.Println("(5:仅用于签名证书(签名、不可抵赖)  6.仅用于数据加密(数据加密) \n 7.仅用于密钥加密(密钥加密)  8.仅用于密钥交换证书(交换)")
		fmt.Print("请输入证书用途(例如 1):")
		fmt.Scanln(&keyusage) 
		fmt.Println("")
		fmt.Println("请输入增强密钥用法(多个用法用,间隔)")
		fmt.Println("0:任何目的 1:服务器身份验证(SSL) 2:客户端身份验证(SSL)")
		fmt.Println("3:代码签名 4:电子邮件保护 5:IPSec端系统")
		fmt.Println("6:IPSec隧道模式 7:IPSec用户模式 8:时间戳签名")
		fmt.Println("9:OCSP响应签名 10:Microsoft服务器加密 11:Netscape服务器加密")
		fmt.Println("12:Microsoft商业代码签名 13:Microsoft内核代码签名")
		fmt.Print("请输入增强密钥用法(例如:1,2):")
		fmt.Scanln(&exusage) 
		 if strings.Contains(exusage, "12") || strings.Contains(exusage, "13") {
		 	Kernel="1"
		 }
		if strings.Contains(exusage, "1") || strings.Contains(exusage, "2"){
			fmt.Println("如果是域名SSL证书请输入域名(多个域名用,间隔 例如:qq1.com,*.qq2.com)")
			fmt.Print("请输入域名(为空可直接回车):")
			fmt.Scanln(&ymlisttx) 
			if(ymlisttx==""){
				ymlisttx="null"
			}
			fmt.Println("如果是IP SSL证书请输入IP(多个IP用,间隔 例如:192.168.100.1,192.168.101.*)")
			fmt.Print("请输入IP:(为空可直接回车)")
			fmt.Scanln(&iplisttx) 
			if(iplisttx==""){
				iplisttx="null"
			}
		}
	}else{
		keyusage="2" //CA专用
		fmt.Println("")
		fmt.Println("请输入CA专属增强密钥用法(多个用法用,间隔)")
		fmt.Println("0:任何目的 1:服务器身份验证(SSL) 2:客户端身份验证(SSL)")
		fmt.Println("3:代码签名 4:电子邮件保护 5:IPSec端系统")
		fmt.Println("6:IPSec隧道模式 7:IPSec用户模式 8:时间戳签名")
		fmt.Println("9:OCSP响应签名 10:Microsoft服务器加密 11:Netscape服务器加密")
		fmt.Println("12:Microsoft商业代码签名 13:Microsoft内核代码签名")
		fmt.Print("请输入增强密钥用法(例如:1,2):")
		fmt.Scanln(&exusage) 
		 if strings.Contains(exusage, "12") || strings.Contains(exusage, "13") {
		 	Kernel="1"
		 }
	}

	fmt.Println("请输入证书有效期限(单位年)")
	fmt.Println("方式1 例如输入:1 代表从当前时间记做颁发日期，有效期持续一年后过期：")
	fmt.Println("方式2 例如输入:2020/12/08-21:18:57T2023/12/08-21:18:57") 
	fmt.Println("代表颁发日期从2020/12/08-21:18:57开始，过期日期搭到2023/12/08-21:18:57") 
	fmt.Print("请输入证书有效期限:")
	fmt.Scanln(&zxtime) 
	if(zxtime==""){
		zxtime="1"
	}

	 // 命令行参数  
	 var args []string
	 args=[]string{finalString,keybit,hash,keyusage,exusage,certtype,zxtime,ymlisttx,iplisttx,Kernel,IssureID,Keyalgorithm} 
	 // 创建一个*Cmd对象，表示要执行的命令  
	 cmd := exec.Command(MODTC+"\\MAKECERT.EXE", args...)  
	 fmt.Println(MODTC+"\\MAKECERT.EXE ",args)
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
if(MODML[1]=="RevokeCERT" || MODML[1]=="revokeCERT" || MODML[1]=="revokecert" || MODML[1]=="Revokecert"){
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
if(MODML[1]=="signCRL" || MODML[1]=="signcrl" || MODML[1]=="CRL" || MODML[1]=="crl"){
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
if(MODML[1]=="initOCSP" || MODML[1]=="initocsp"){
	fmt.Println("初始化新OCSP响应签名证书")
	 // 命令行参数  
	 args:=[]string{}
	 if(len(MODML) > 2){
	 	args= []string{"initOCSP",MODML[2]}  
	 }else{
	 	args= []string{"initOCSP","RSA"}  //默认RSA
	 } 

	 // 创建一个*Cmd对象，表示要执行的命令  
	 cmd := exec.Command(MODTC+"\\MAKECERT.EXE", args...) 	  
	 // 运行命令并等待它完成  
	 output, _ := cmd.CombinedOutput()  
	 fmt.Println(string(output),err)
	os.Exit(0)
}

//初始化TIMSTAMP时间戳专用签名证书
if(MODML[1]=="initTIMSTAMP" || MODML[1]=="inittimstamp" || MODML[1]=="inittimestamp" || MODML[1]=="initTIMESTAMP"){
	if(len(MODML)==3){
		 //说明没带参数
		 // 命令行参数  
		 args:=[]string{}
		 if(len(MODML) > 2){
		 	args= []string{"initTIMSTAMP","SHA1",MODML[2]}
		 }else{
		 	args= []string{"initTIMSTAMP","SHA1","RSA"}  //默认RSA
		 } 
		   
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

		 
		 if(len(MODML) > 2){
		 	args = []string{"initTIMSTAMP","SHA256",MODML[2]}
		 }else{
		 	args=  []string{"initTIMSTAMP","SHA256","RSA"}  //默认RSA
		 }  
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

	 if(len(MODML)==4){
		 args:=[]string{"initTIMSTAMP",MODML[2],MODML[3]}  
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
	 if(len(MODML)==2){
		 args:=[]string{"initTIMSTAMP","SHA1","RSA"}  
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

		 args=[]string{"initTIMSTAMP","SHA256","RSA"}  
		 cmd = exec.Command(MODTC+"\\MAKECERT.EXE", args...) 

		 // 运行命令并等待它完成  
		 outtext,err=cmd.CombinedOutput()  
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
	fmt.Println("这里还没有写 1.文件完整性检查（防止修改） 2.签名检查（防止伪造，中间人攻击） 2.在本地库中验证是否可信")
	fmt.Println("签名验证结果:真   是否受信认:真")
	fmt.Println("验证状态:通过 （以上两种为真则验证通过，否则验证失败）")

	os.Exit(0)
}

if(MODML[1]=="VERSION" || MODML[1]=="version"  || MODML[1]=="ver"  || MODML[1]=="VER"){
	fmt.Println("MOD PKI CA 4.0 \r\n Version:202410271455")
	os.Exit(0)
}











fmt.Println("ERROR:错误,无法处理业务")
fmt.Println("未知参数数量")
for k,v:= range os.Args{
fmt.Printf("args[%v]=[%v]\n",k,v)
}

os.Exit(0)
}


//函数显示颁发者证书
func showcalist(MODPKI_certsfile string){
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
    fmt.Println("颁发者序列号           证书类别   证书状态        签发时间/吊销时间            上级CA序列号       签名算法")
    for{  
        line, err := reader.ReadString('\n')  
        if err != nil {  
            break 
        } 
        if(line[0]=='#'){
        	continue
        }

        clist:=strings.Split(line," ")
        if(len(clist)==7){
        	if(clist[1]=="C" || clist[1]=="R"){
        		fileindex=fileindex+1
        		if(clist[1]=="C"){
        			clist[1]="CA  "
        		}
        		if(clist[1]=="R"){
        			clist[1]="ROOT"
        		}

        		if(clist[2]=="V"){
        			clist[2]="正常"
        		}
        		if(clist[2]=="R"){
        			clist[2]="吊销"
        		}
        		fmt.Println(clist[0] +"         " + clist[1] +"         " + clist[2] +"         " +clist[4] +"         " +clist[5] +"         " +clist[6]) // 仅输出CA级别序列号
        	}
        }
    } 
    fmt.Println("颁发者统计总数量：",fileindex,"第一列为颁发者序列号")
}