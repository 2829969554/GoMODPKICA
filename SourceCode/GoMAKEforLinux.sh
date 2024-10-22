#没写 等源码没有BUG了我就编译linux版本可执行文件
#我已经在linux下编译通过了，不过因为windows系统取命令行和linux下取命令行 不太一样有很严重的运行流程问题
#例如 在win下运行 admin.exe value1 value2  在go中取命令行 [0] 为admin.exe  [1]value1  [2]value2
#例如 在linux下运 admin.elf value1 value2  在go中取命令行 [0] 为/home/desktop/admin.elf [1] admin.elf [2]value1  [3]value2
#上述这种情况需要我自行处理字符串，工作量不少 而且linux不常用，我目前优先写新功能和修复bug，最后再整理linux版本的
#2024/07/12 19:44