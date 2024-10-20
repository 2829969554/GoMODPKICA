更新日志

2024年10月20日 14:14
  1.修复BUG 补充代码注释
  2.引用sct.go  X509 PKIX SCT列表
  3.引用cps.go  X509 PKIX 证书策略
  3.格式化代码
     //统一向证书模板加入上面的pkix扩展信息
     template.ExtraExtensions = []pkix.Extension{
         ctExtension,mycps,
     }

2024年10月6日 23：24
sm_demo.go
代码行号 104至128 作用 生成SCT列表数据 sctasn1byte

     // 创建一个CT扩展 证书透明度
     ctExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
        Critical: false,
        Value: sctasn1byte,
     }


2024年9月16日23点

sm_demo.go 文件中行号 59至67 是生成X509扩展【证书策略】结构扩展数据，自定义 策略数据 用户通告 OID列表


[1]Certificate Policy:
     Policy Identifier=2.23.140.1.4.1
     [1,1]Policy Qualifier Info:
          Policy Qualifier Id=CPS
          Qualifier:
               https://d.symcb.com/cps
     [1,2]Policy Qualifier Info:
          Policy Qualifier Id=用户通告
          Qualifier:
               Notice Text=你好
[2]Certificate Policy:
     Policy Identifier=2.23.140.1.4.2

