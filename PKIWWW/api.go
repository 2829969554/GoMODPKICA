package main
//公共函数文件  
import (  
 //"fmt"  
 "os"  
 "strings"  
 "bufio"
 "io/ioutil" 
)  

/* 
func main() {  
    
    //读取MODPKICA数据文件 返回二维数组格式
    MODPKIreadline("a.txt",5)
    //将正常的指定参数整行数据标记为已删除
    fmt.Println(MODPKIlineUnote("a.txt","2"))
    //将已删除的指定参数整行数据标记为正常
    fmt.Println(MODPKIlineRnote("a.txt","2"))
    //向MODPKICA数据文件 追加指定行数据
    fmt.Println(MODPKIaddline("a.txt","8 9 0 9 8"))
    //读取MODPKICA数据文件 提取指定参数整行数据的数组格式
    fmt.Println(MODPKIgetline("a.txt","2"))
   
}
*/ 

/*
MODPKICA系统专用函数
作用：打开文件并且返回二维数组
返回的数组结构：[行号][参数项目(0-rowlen)]
传入文件结构：文本文件的每行作为数组结构中的行号  使用空格分隔每行文本作为数组结构中的参数项目

函数参数 path 是文件地址,rowlen是每行的参数数量
函数返回值 二维数组，错误标识
*/
func MODPKIreadline(path string,rowlen int) (string [][]interface{},errs error){
     // 打开文件  
     file, err := os.Open(path)  
     if err != nil {  
         return  nil,err
     }  
     defer file.Close()  
     // 创建一个新的Scanner来读取文件内容  
     scanner := bufio.NewScanner(file)  
     // 创建一个空的一维切片，用于存储二维数组的行  
     rows := make([][]interface{}, 0) 
     for scanner.Scan() {  
         line := scanner.Text() // 读取一行文本  
         // 检查行是否以#开头，如果是则跳过这行  
         if strings.HasPrefix(line, "#") {  
          continue  
         }  
if(len(line)<=5){
     continue     
}
         // 使用空格分隔行数据  
         fields := strings.Split(line, " ") 
         if(len(fields)==rowlen){
            row := []interface{}{} 
            for i := 0; i < rowlen; i++ {
                tmprow:= []interface{}{fields[i]} 
                row=append(row,tmprow)
            }
              
             rows = append(rows, row) 
         }

     }  
      
     if err := scanner.Err(); err != nil {  
        return nil,err
     } 
     //fmt.Println(len(rows),rows[0][0],rows[1][0],rows[2][0],rows[3][0]) 
     return rows,nil
}
/*
MODPKICA系统专用函数
作用：从指定参数的参数项目开头增加字符#实现记录从 正常标记变更为删除 的功能
函数参数 path 是文件地址,args是每行数据的的参数0的值
函数返回值 逻辑型号 真|假  代表操作状态
*/
func MODPKIlineUnote(path string,args string)(isok bool){
 // 打开文件  
 file, err := os.Open(path)  
 if err != nil {  
  return  false
 }  
 defer file.Close()  
  
 // 创建一个新的Scanner来读取文件内容  
 scanner := bufio.NewScanner(file)  
 for scanner.Scan() {  
 line := scanner.Text() // 读取一行文本  
 // 检查行是否以#开头，如果是则跳过这行  
 if strings.HasPrefix(line, "#") {  
    continue  
 }  
  
 // 使用空格分隔行数据  
if(len(line)<=5){
     continue     
}
 fields := strings.Fields(line)  
     if(fields[0]==args){
        content,_:= ioutil.ReadFile(path) 
        modifiedContent := strings.Replace(string(content), line, "#"+line, -1)
         err = ioutil.WriteFile(path, []byte(modifiedContent), 0644)  
         if err != nil {  
            return  false
         } 
        return true
     }

 }  
 return  false  
}

/*
MODPKICA系统专用函数
作用：从指定参数的参数项目开头删除字符#实现记录从 删除标记变更为正常 的功能
函数参数 path 是文件地址,args是每行数据的的参数0的值
函数返回值 逻辑型号 真|假  代表操作状态
*/
func MODPKIlineRnote(path string,args string)(isok bool){
 // 打开文件  
 file, err := os.Open(path)  
 if err != nil {  
  return  false
 }  
 defer file.Close()  
  
 // 创建一个新的Scanner来读取文件内容  
 scanner := bufio.NewScanner(file)  
 for scanner.Scan() {  
 line := scanner.Text() // 读取一行文本  
 // 检查行是否以#开头，如果是则跳过这行  
 if strings.HasPrefix(line, "#") {  
 if(len(line)<=5){
     continue     
} 
 // 使用空格分隔行数据  
 fields := strings.Fields(line)  
     if(fields[0]=="#"+args){
        content,_:= ioutil.ReadFile(path) 
        modifiedContent := strings.Replace(string(content), line, line[len(line)-(len(line)-1):], -1)
         err = ioutil.WriteFile(path, []byte(modifiedContent), 0644)  
         if err != nil {  
            return  false
         } 
        return true
     }
 }  

 }  
return  false
}


/*
MODPKICA系统专用函数
作用：向path文件末尾 追加 参数列表内容args
函数参数 path 是文件地址,追加记录参数列表内容例如:1 2 3 4 5 6
函数返回值 逻辑型号 真|假  代表操作状态
*/
func MODPKIaddline(path string,args string)(isok bool){
 // 打开文件，使用追加模式  
 file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)  
 if err != nil {  
    return false
 }  
 defer file.Close()  
   
 _, err = file.WriteString(args+"\n")  
 if err != nil {  
    return false 
 }  
  
return true
}



/*
MODPKICA系统专用函数
作用：返回指定参数列表0的值所在行的数据的数组格式
函数参数 path 是文件地址,arg 是参数列表0的值
函数返回值 一维数组 ，逻辑型 真|假
*/
func MODPKIgetline(path string,arg string)(string []string,isok bool){
 // 打开文件  
 file, err := os.Open(path)  
 if err != nil {  
  return nil,false
 }  
 defer file.Close()  
  
 // 创建一个新的Scanner来读取文件内容  
 scanner := bufio.NewScanner(file)  
 for scanner.Scan() {  
 line := scanner.Text() // 读取一行文本  
 // 检查行是否以#开头，如果是则跳过这行  
 if strings.HasPrefix(line, "#") {  
  continue
 }  
 if(len(line)<=5){
     continue     
}
 // 使用空格分隔行数据  
 fields := strings.Fields(line)  
     if(fields[0]==arg){
        return fields,true
     }  
}
return nil,false
}
