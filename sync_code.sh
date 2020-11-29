#!/bin/bash

rsync -a --exclude='/.git' --filter="dir-merge,- .gitignore" \
	/media/sf_jiaqingtong/Workplace/git/linux-mips/ `pwd`
sed -i 's/march=octeon/march=octeon2/g' arch/mips/Makefile
