#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#define NORMAL "\x1B[0m"
#define RED "\x1B[31;1m"
#define WHITE "\x1B[37;1m"

int f_check(char* fileName);
int f_check_elf(int32_t fd, Elf64_Ehdr* header);
void f_usage(char* argv);
void info_header(Elf64_Ehdr header);
void print_section(Elf64_Ehdr header, Elf64_Shdr* shdr, int fd);
void print_symbols(Elf64_Ehdr header, Elf64_Shdr* shdr, int fd);

#endif