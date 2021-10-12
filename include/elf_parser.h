#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <stdint.h>
#include <stdlib.h>

#include "proc.h"

void info_header(child_proc *);
int info_sections(child_proc *);
void print_flag_shdr(uint64_t );
int info_segements(child_proc *);
char *print_flag_phdr(uint32_t );
char *print_type_shdr(uint32_t );
char *print_type_phdr(long long );
char *print_type_ehdr(unsigned char );
char *print_osabi_ehdr(unsigned char );
char *print_machine_ehdr(unsigned char );
int check_elf_file(int32_t , Elf64_Ehdr *);
Elf64_Shdr *get_shdr(int , Elf64_Shdr *, Elf64_Ehdr);
Elf64_Phdr *get_phdr(int , Elf64_Phdr *, Elf64_Ehdr);

void print_symbols(Elf64_Ehdr header, Elf64_Shdr* shdr, int fd);

#endif

