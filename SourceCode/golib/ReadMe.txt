重要文件，目前只测试过以下版本
支持GO版本：go version go1.20.3 windows/amd64


第一.需要将pkix.go文件复制到%GO_HOME%\src\crypto\x509\pkix\目录下，
	注意备份此目录下的原pkix.go文件，其他go版本不知道能不能替换。

	#文件中pkix.Name结构体（这个文件我扩展了这三个对象标识符）
	"EVTYPE":"2.5.4.15"  //扩展验证类型 例如Private Organization
	"EVCITY":"1.3.6.1.4.1.311.60.2.1.2"//城市名称例如beijing
	"EVCT":  "1.3.6.1.4.1.311.60.2.1.3"  //国家名称例如CN
	"EMAIL": "1.2.840.113549.1.9.1"
	# 2023/12/06 14:47 编写

	
第二.需要将文件夹ocsp复制到%GO_HOME%\src\crypto\目录下，
	此目录下原本应该没有ocsp文件夹，其他go版本如果有那我也不知道能不能替换。
	我的版本go version go1.20.3 windows/amd64 
	# 2023/12/09 18:33 编写
	
	
第三.需要将文件夹pkcs7复制到%GO_HOME%\src\crypto\x509\目录下，
	此目录下原本应该没有pkcs7文件夹，其他go版本如果有那我也不知道能不能替换。
	
	这是编译时间戳服务Authenticode相关服务必要的GO包
	我的版本go version go1.20.3 windows/amd64 
	# 2023/12/10 14:33 编写

	
第四.(高版本不可选)需要将文件x509.go复制到%GO_HOME%\src\crypto\x509\目录下，
	此目录下原本有x509.go文件，但是它默认把sha1哈希算法禁用了 ，我为了启用SHA1就把他部分代码屏蔽了 
	其他go版本如果有那我也不知道能不能替换。
	我的版本go version go1.20.3 windows/amd64 
	# 2023/12/12 20:40 编写
	高版本不可选例如go version go1.22.5 windows/amd64 不用复制该文件！！
	# 2024/08/11 14:52

	
第五.需要将文件夹timestamp复制到%GO_HOME%\src\crypto\目录下，
	此目录下原本应该没有timestamp文件夹，其他go版本如果有那我也不知道能不能替换。
	
	这是编译时间戳服务RFC3161相关服务必要的GO包
	我的版本go version go1.20.3 windows/amd64 
	# 2023/12/12 20:40 编写

第六.将tjfoc文件夹复制到%GO_HOME%\src\目录下面，
	本库提供SHA3,RIPEMD,SM2,SM3,SM4相关算法支持
	我的版本go version go1.22.5 windows/amd64
	# 2024/08/18 14:26 编写
	SM2证书修复签名错误的BUG
	# 2024/10/21 13:10 编写


第七.将modcrypto文件夹复制到%GO_HOME%\src\目录下面，
	本库提供NEW SHA3,RIPEMD,SM2,SM3,SM4相关算法支持
	我的版本go version go1.22.5 windows/amd64
	# 2024/08/23 23:16 编写
	SM2证书修复签名错误的BUG
	# 2024/10/21 13:10 编写