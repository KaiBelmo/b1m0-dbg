#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <elf.h>
#include <sys/mman.h>

void f_usage(char* argv);
int	f_check(char* fileName);
int	f_check_elf(int32_t fd, Elf64_Ehdr *header);

void info_header(Elf64_Ehdr header);
void print_section(Elf64_Ehdr header, Elf64_Shdr* shdr, int fd);
void print_symbols(Elf64_Ehdr header, Elf64_Shdr* shdr, int fd);

#endif
