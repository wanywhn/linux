#!/bin/bash

#mips64el-linux-gnuabi64-strip vmlinux
cp vmlinux /media/sf_jiaqingtong/Workplace/git/linux-mips/
#make ARCH=mips CROSS_COMPILE=mips64el-linux-gnuabi64- modules_install INSTALL_MOD_PATH=/home/tender/workplace/linux-mips/modules_mips
#tar cvJf modules.tar.xz modules_mips
#cp modules.tar.xz /media/sf_jiaqingtong/Workplace/git/linux-mips/
