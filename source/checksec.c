#include "dbg.h"
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include "checksec.h"

void check_relro(Elf64_Phdr *elf_phdr, size_t e_phnum){
  printf(WHITE"RELRO: "NORMAL);
  for (size_t i = 0; i < e_phnum; i++)
  {
    if (elf_phdr[i].p_type == PT_GNU_RELRO)
    {
      printf("Full RELRO\n");
      return;
    }
  }
  printf("No RELRO\n");
}

void check_NX(Elf64_Phdr *elf_phdr, size_t e_phnum){
  printf(WHITE"NX: "NORMAL);
  for (size_t i = 0; i < e_phnum; i++)
  {
    if (elf_phdr[i].p_type == PT_GNU_STACK && elf_phdr[i].p_flags != (PF_W | PF_R | PF_X))
    {
      printf("NX enabled\n");
      return;
    }
  }
  printf("NX disabled\n");
}

void check_aslr(Elf64_Ehdr elf_ehdr){
  printf(WHITE"ASLR: "NORMAL);
  if (elf_ehdr.e_type == ET_DYN)
  {
      printf("PIE enabled\n");
      return;
  }
  printf("No PIE\n");
}

void check_stack_canary(void){
  printf(WHITE"STACK CANARY: "NORMAL);
  unimplemented();
} 