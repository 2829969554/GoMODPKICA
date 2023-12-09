 -alias <alias>          要处理的条目的别名
 -keyalg <alg>           密钥算法名称
 -keysize <size>         密钥位大小
 -groupname <name>       组名。例如，椭圆曲线名称。
 -sigalg <alg>           签名算法名称
 -dname <name>           唯一判别名
 -startdate <date>       证书有效期开始日期/时间
 -ext <value>            X.509 扩展
 -validity <days>        有效天数
 -keypass <arg>          密钥口令
 -keystore <keystore>    密钥库名称
 -signer <alias>         签名者别名
 -signerkeypass <arg>    签名者密钥密码
 -storepass <arg>        密钥库口令
 -storetype <type>       密钥库类型
 
 
::ROOT
-genkeypair -genkey
keytool -genkeypair -alias ROOT -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -keystore ROOT.jks  -dname "CN=www.boc.cn, O=Bank of China Limited, ST=Beijing, C=CN, serialNumber=911000001000013428, 2.5.4.15=Private Organization, 1.3.6.1.4.1.311.60.2.1.2=Beijing, 1.3.6.1.4.1.311.60.2.1.3=CN" -storepass 123456 -ext "keyUsage=KeyCertSign,CrlSign" 

-ext ""

::参数
::-sigalg MD5withRSA SHA1withRSA SHA224withRSA SHA256withRSA SHA384withRSA SHA512withRSA 

::-startdate 2023/07/01
::-validity 30


::正常使用

::Critical 严格模式

::Subject Information Access (SIA)
-ext "SIA=caIssuers:URI:https://2.5.1"

::颁发者可选名称
-ext "IAN=DNS:2.5.1"

::使用者可选名称
-ext "san=ip:127.0.0.1,dns:localhost"

::CRL Distribution Points (CDP)
-ext "crlDistributionPoints=URI:https://evca.crl,URI:https://2.crl" 

::Authority Information Access (AIA)
-ext "AuthorityInfoAccess=caIssuers:URI:https://ga.com,OCSP:URI:https://g.ocsp" 

::Basic Constraints 基本约束
-ext "BasicConstraints:Critical=CA:true,PathLen:0" 

::密钥用法
-ext "keyUsage=KeyCertSign,CrlSign" 

::扩展密钥用法
-ext "ExtendedKeyUsage=OCSPSigning,AdobePDFSigning,DocumentSigning,CodeSigning,Email,TimeStamping,TSLSigning" 

::使用者可选名称
-ext "SubjectAlternativeName=DNS:a.b.c" 



::--------------------------





::无法使用
::-ext "CertPolicy=URL:http://123.123"
::-ext "SubjectInformatonAccess=URL:http://123.123"
::-ext "2.5.29.14=hash" 
::-ext "2.5.29.32:2.23.140.1.3:1.2.3.4"
::-ext "2.5.29.37=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2"


keytool -export -alias ROOT -file ROOT.crt -keystore ROOT.jks -storepass 123456
