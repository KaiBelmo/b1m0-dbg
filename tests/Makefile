all: sigtrap syscalls string_cmp

sigtrap: sigtrap.asm
	nasm -felf64 sigtrap.asm
	@ld sigtrap.o -o sigtrap.out
	@rm sigtrap.o

syscalls: syscalls.asm
	nasm -felf64 syscalls.asm
	@ld syscalls.o -o syscalls.out
	@rm syscalls.o

string_cmp: string_cmp.c
	gcc -o string_cmp.out string_cmp.c -fno-stack-protector -z execstack -no-pie -m64

clean:
	@echo "clean!"
	@rm *.out
