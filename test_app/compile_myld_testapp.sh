#!/bin/sh

gcc -g -O0 -nostdinc -I/home/myld_test/src/inc -Wl,--rpath=/home/myld_test/src -Wl,-I/home/myld_test/src/myld -nostdlib -fno-builtin -Wl,-e,main hello.c /home/myld_test/src/myld -o hello

