#ifndef CHECKSEC_H
#define CHECKSEC_H

#include <elf.h>
#include <stdlib.h>

void check_relro(Elf64_Phdr *, size_t );
void check_NX(Elf64_Phdr *, size_t );
void check_aslr(Elf64_Ehdr );
void check_stack_canary(void);

#endif