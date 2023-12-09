::需要鼠标右键单击 使用管理员模式运行
::作用安装root.crt到系统可信证书库
certutil -addstore -f Root %~dp0root.crt
::安装root.crt到系统第三方可信证书库
certutil -addstore -f AuthRoot %~dp0root.crt