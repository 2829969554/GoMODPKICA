
::初始化颁发机构
certstrap.exe init --passphrase "123456" --common-name "MOD PKI ROOT" --key-bits 2048 --expires "120 months" --organization "O" --organizational-unit "OU" --country "CN" --province "ST" --locality "L" 

::创建CA证书申请和密钥
certstrap request-cert --passphrase "123456" --common-name "MODCA" --key-bits 2048 --organization "O" --organizational-unit "OU" --country "CN" --province "ST" --locality "L" --ip "192.168.101.152" --domain "ABC.COM" --uri "http://abc.com"

::由ROOT签发CA证书
certstrap sign "MODCA" --expires "12 months"  --CA "MOD PKI ROOT" --passphrase "123456" --intermediate


::创建用户证书申请和密钥
certstrap request-cert --passphrase "123456" --common-name "qqcom" --key-bits 2048 --organization "O" --organizational-unit "OU" --country "CN" --province "ST" --locality "L" --ip "192.168.101.1" --domain "qq.com" --uri "http://qq.com"

::由CA签发用户证书
certstrap sign "qqcom" --expires "12 months"  --CA "MODCA" --passphrase "123456"


::ROOT吊销CA证书 有错误
certstrap revoke --CN "MODCA" --CA "MOD PKI ROOT"

certstrap revoke --CN "B" --CA "A"
