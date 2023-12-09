package main  
  
import (  
 "bufio"  
 "fmt"  
 "os"    
 "path/filepath"
 "strings"
 "strconv"
)  
  
func main() {  

 ex, err := os.Executable()  
 if err != nil {  
 panic(err)  
 }  

//当前执行目录
MODTC:= filepath.Dir(ex)  
//所有证书记录表
MODPKI_certsfile:=MODTC+"\\PKI\\CERTS.txt"
 // 打开文本文件  
 file, err := os.Open(MODPKI_certsfile)  
 if err != nil {  
 fmt.Println("无法打开文件:", err)  
 return  
 }  
 defer file.Close()  
  
 // 创建一个Scanner来读取文件内容  
 reader := bufio.NewReader(file)  
  

    // 循环读取每一行  
    for{  
        line, err := reader.ReadString('\n')  
        if err != nil {  
            break 
        } 
        if(line[0]=='#'){
            continue
        }
        
        fmt.Println(line) // 输出这一行  
         // 使用空格分隔每行文本  
         fields := strings.Split(line," ")  
         // 输出分隔后的结果  
         fmt.Println(fields[0],fields[2],fields[3])
         if(fields[2]=="R"){
             num, err := strconv.ParseInt(fields[0],16,64)  
             if err != nil {  
             fmt.Println("转换失败:", err)   
             }
             fmt.Println(num)   
         } 
 
    } 
 
}