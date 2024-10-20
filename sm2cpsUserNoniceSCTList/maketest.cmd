@echo off
go build sm_demo.go cps.go sct.go
go build sm2verify.go
go build smcrl.go
call  sm_demo.exe
call smcrl.exe
call sm2verify.exe

pause