更新日志

2024年10月20日 14:14
  1.修复BUG 补充代码注释
  2.引用sct.go  X509 PKIX SCT列表
  3.引用cps.go  X509 PKIX 证书策略
  3.格式化代码


2024年10月6日 23：24
sm_demo.go
代码行数 296 -345 作用 生成b，SM2签名

      // 创建一个CT扩展 证书透明度
    ctExtension := pkix.Extension{
        Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
        Critical: false,
        Value: b   ,
        }
    //向证书模板加入证书透明度信息
    template.ExtraExtensions = []pkix.Extension{
       ctExtension,
    }


2024年9月16日23点

sm_demo.go 文件中行号 74-100 是证书策略结构，目前无法自动计算长度，需要整理成自定义多个策略




[1]Certificate Policy:
     Policy Identifier=1.3.6.1.4.1.6449.1.2.1.6.1
     [1,1]Policy Qualifier Info:
          Policy Qualifier Id=CPS
          Qualifier:
               https://sectigo.com/CPS
[2]Certificate Policy:
     Policy Identifier=2.23.140.1.3
