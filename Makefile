CC=gcc
ASM=nasm

all: shellcode_runner shellcode

shellcode_runner: shellcode_runner.o
	$(CC) shellcode_runner.o -o shellcode_runner

shellcode:
	$(ASM) -f bin -o shellcode shellcode.asm

clean:
	rm shellcode_runner.o shellcode_runner shellcode
