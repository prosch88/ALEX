Mtk-su is a superuser tool for Mediatek 64-bit Android devices,
developed by diplomatic@XDA.

OPTIONS

mtk-su [-v] [-s | -c <command>] [-Z <context>]

-v
	Verbose mode
-s
	Print kernel symbol table
-c
	Try to run command <command> as superuser. Default /system/bin/sh.
-Z
	Run shell/command in the selinux <context>

FLAVORS
arm64: 64-bit kernel and userspace
arm: 32-bit or 64-bit kernel and userspace

To get a temporary privileged shell:
1. Push mtk-su to /data/local/tmp
2. Give exec permissions to mtk-su
3. Run ./mtk-su
