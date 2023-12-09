::window证书管理区名称
::AddressBook  其他用户的 X.509 证书存储区。
::AuthRoot  第三方证书颁发机构 (CA) 的 X.509 证书存储区。
::CertificateAuthority 中间证书颁发机构 (CA) 的 X.509 证书存储区。
::Disallowed 吊销的证书的 X.509 证书存储区。
::My   个人证书的 X.509 证书存储区。
::Root 受信任的根证书颁发机构 (CA) 的 X.509 证书存储区。
::TrustedPeople   直接受信任的人和资源的 X.509 证书存储区。
::TrustedPublisher 直接受信任的发行者的 X.509 证书存储区。



::通用参数
::-h 1 2 3 4 5 6指定最大颁发层次
::-cy 指定证书的基本约束 end(最终实体) 或者 authority（颁发机构）

::-len 512 1024 2048 4096 8192
::-a MD5 SHA1 SHA256 sha384 SHA512
::-r 指定为根证书
::-# 指定证书序列号
::-$ 指定证书的签名权限，必须设置为 commercial（对于商业软件发行者使用的证书）或 individual（对于个人软件发行者使用的证书）。
::-l 指定颁发策略 https://www.baidu.com 
::-b 指定生效日期 11/10/2001
::-e 指定失效日期 11/10/2031
::-m 指定证书有效月份 1   从当前时间开始到一个月后失效（不能和-b -e 同时存在）

::-eku 增强密钥用法
::1.3.6.1.5.5.7.3.3 指示证书对代码签名有效。 始终指定此值以限制证书的预期用途。
::1.3.6.1.4.1.311.10.3.13 表示证书遵循生存期签名。 通常，如果签名带有时间戳，只要证书在时间戳时有效，即使证书过期，签名也仍然有效。 无论签名是否带有时间戳，此 EKU 都会强制签名过期。





::颁发子证书参数
::-ic 颁发者cer
::-iv 颁发者pvk

::ROOT
makecert -b 11/10/2001 -e 11/10/2031 -n "CN=RA, O=RA Limited, ST=Beijing, C=CN" -r -cy authority -# 01 -len 4096 -a SHA256 -sv root.pvk root.cer

::CA 
makecert -b 11/10/2001 -e 11/10/2031 -n "CN=CA, O=CA Limited, ST=Beijing, C=CN" -cy authority -# 02 -len 2048 -a SHA256 -iv root.pvk -ic root.cer -sv ca.pvk ca.cer

::用户 EV
makecert -m 1 -n "CN=www.boc.cn, O=Bank of China Limited, ST=Beijing, C=CN, serialNumber=911000001000013428, 2.5.4.15=Private Organization, 1.3.6.1.4.1.311.60.2.1.2=Beijing, 1.3.6.1.4.1.311.60.2.1.3=CN" -cy end -# 03 -len 2048 -a SHA256 -eku 1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.13 -$ commercial -l http://xxx -iv ca.pvk -ic ca.cer -sv end.pvk  end.cer 

::SPC发布者证书
cert2spc.exe end.cer end.spc

::pfx签名包
::-pi 可指定PFX密码
pvk2pfx.exe -f -pvk end.pvk -spc end.spc -pfx end.pfx


::CRL 证书吊销列表
makecert.exe -crl -sv root.pvk -sc root.cer -a sha256 root.crl 

