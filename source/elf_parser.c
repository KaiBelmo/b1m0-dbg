#include "dbg.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "elf_parser.h"

int check_elf_file(int32_t fd, Elf64_Ehdr *elf_header)
{
  if (read(fd, elf_header->e_ident, sizeof(Elf64_Ehdr)) == -1)
  {
    perror("read");
    return -1;
  }
  if ((elf_header->e_ident[0] != ELFMAG0) &&
      (elf_header->e_ident[1] != ELFMAG1) &&
      (elf_header->e_ident[2] != ELFMAG2) &&
      (elf_header->e_ident[3] != ELFMAG3))
  {
    return fprintf(stderr, "ERROR: Not a valid elf file.\n");
  }
  if (elf_header->e_ident[EI_CLASS] == ELFCLASSNONE)
  {
    fprintf(stderr, "ERROR: Not a valid elf file.\n");
    return -1;
  }
  if (elf_header->e_ident[EI_CLASS] == ELFCLASS32)
  {
    fprintf(stderr, "ERROR: 32-bit elf file.\n");
    return -1;
  }
  return 0;
}

void info_header(child_proc *proc)
{
  printf(WHITE "ELF Header:\n" NORMAL);
  printf(WHITE " Magic:\t\t" NORMAL);
  for (int i = 0; i < EI_NIDENT; i++)
  {
    printf("%02x ", proc->elf_ehdr.e_ident[i]);
  }
  printf(WHITE "\n Class:\x1B[0m\t\t%s",
         (proc->elf_ehdr.e_ident[EI_CLASS] == ELFCLASS64) ? "ELF64" : "ELF32");
  printf(WHITE "\n Data:\x1B[0m\t\t%s",
         (proc->elf_ehdr.e_ident[EI_DATA] == ELFDATA2LSB) ? "2's complement, little endian" : "2's complement, big endian");
  printf(WHITE "\n Version:\x1B[0m\t%s",
         (proc->elf_ehdr.e_ident[EI_VERSION] == EV_CURRENT) ? "1 (Current version)" : "Invalid version");

  printf(WHITE "\n OS/ABI:\x1B[0m\t%s", print_osabi_ehdr(proc->elf_ehdr.e_ident[EI_OSABI]));
  printf(WHITE "\n ABI Version:\x1B[0m\t%d", (proc->elf_ehdr.e_ident[EI_ABIVERSION]));
  printf(WHITE "\n Type:\x1B[0m\t\t%s", print_type_ehdr(proc->elf_ehdr.e_type));
  printf(WHITE "\n Machine:\x1B[0m\t%s", print_machine_ehdr(proc->elf_ehdr.e_machine));
  printf(WHITE "\n Version:\x1B[0m\t0x%x", proc->elf_ehdr.e_version);
  printf(WHITE "\n Entry point address:\x1B[0m\t\t\t0x%lx", proc->elf_ehdr.e_entry);
  printf(WHITE "\n Start of program headers:\x1B[0m\t\t0x%lx - bytes into file", proc->elf_ehdr.e_phoff);
  printf(WHITE "\n Start of section headers:\x1B[0m\t\t0x%lx - bytes into file", proc->elf_ehdr.e_shoff);
  printf(WHITE "\n Flags:\x1B[0m\t\t\t\t\t0x%x", proc->elf_ehdr.e_flags);
  printf(WHITE "\n Size of this header:\x1B[0m\t\t\t0x%x - bytes", proc->elf_ehdr.e_ehsize);
  printf(WHITE "\n Size of program headers:\x1B[0m\t\t0x%x - bytes", proc->elf_ehdr.e_phentsize);
  printf(WHITE "\n Number of program headers:\x1B[0m\t\t0x%x", proc->elf_ehdr.e_phnum);
  printf(WHITE "\n Size of section headers:\x1B[0m\t\t0x%x - bytes", proc->elf_ehdr.e_shentsize);
  printf(WHITE "\n Number of section headers:\x1B[0m\t\t0x%x", proc->elf_ehdr.e_shnum);
  printf(WHITE "\n Section header string table index:\x1B[0m\t0x%x", proc->elf_ehdr.e_shstrndx);
}

char *print_osabi_ehdr(unsigned char c)
{
  switch (c)
  {
  case ELFOSABI_SYSV:
    return "UNIX System V ABI";
  case ELFOSABI_HPUX:
    return "HP-UX ABI";
  case ELFOSABI_NETBSD:
    return "NetBSD ABI";
  case ELFOSABI_LINUX:
    return "Linux ABI";
  case ELFOSABI_SOLARIS:
    return "Solaris ABI";
  case ELFOSABI_IRIX:
    return "IRIX ABI";
  case ELFOSABI_FREEBSD:
    return "FreeBSD ABI";
  case ELFOSABI_TRU64:
    return "TRU64 UNIX ABI";
  case ELFOSABI_ARM:
    return "ARM architecture ABI";
  case ELFOSABI_STANDALONE:
    return "Stand-alone embedded ABI";
  default:
    return "Unknown os abi";
  }
}

char *print_type_ehdr(unsigned char c)
{
  switch (c)
  {
  case ET_NONE:
    return "unknown type";
  case ET_REL:
    return "relocatable file";
  case ET_EXEC:
    return "executable file";
  case ET_DYN:
    return "shared object";
  case ET_CORE:
    return "core file";
  default:
    return "Unknown type";
  }
}

char *print_machine_ehdr(unsigned char c)
{
  switch (c)
  {
  case EM_M32:
    return "AT&T WE 32100";
  case EM_SPARC:
    return "Sun Microsystems SPARC";
  case EM_386:
    return "Intel 80386";
  case EM_68K:
    return "Motorola 68000";
  case EM_88K:
    return "Motorola 88000";
  case EM_860:
    return "Intel 80860";
  case EM_MIPS:
    return "MIPS RS3000 (big-endian only)";
  case EM_PARISC:
    return "HP/PA";
  case EM_SPARC32PLUS:
    return "SPARC with enhanced instruction set";
  case EM_PPC:
    return "PowerPC";
  case EM_PPC64:
    return "PowerPC 64-bit";
  case EM_S390:
    return "IBM S/390";
  case EM_ARM:
    return "Advanced RISC Machines";
  case EM_SH:
    return "Renesas SuperH";
  case EM_SPARCV9:
    return "SPARC v9 64-bit";
  case EM_IA_64:
    return "Intel Itanium";
  case EM_X86_64:
    return "AMD x86-64";
  case EM_VAX:
    return "DEC Vax";
  default:
    return "An unknown machine";
  }
}

int info_segements(child_proc *proc)
{
  struct stat statbuff = {0};
  int err = fstat(proc->fd, &statbuff);
  if (err == -1)
  {
    perror("fstat");
    return -1;
  }

  char *tmp = mmap(0, statbuff.st_size, PROT_READ, MAP_PRIVATE, proc->fd, 0);
  if (tmp == MAP_FAILED)
  {
    perror("mmap");
    return -1;
  }
  proc->elf_phdr = (Elf64_Phdr *)(tmp + proc->elf_ehdr.e_phoff);

  printf(" Elf file type %s\n", print_type_ehdr(proc->elf_ehdr.e_type));
  printf(" Entry point 0x%lx\n", proc->elf_ehdr.e_entry);
  printf(" There are %d program headers, starting at offset %ld\n",
         proc->elf_ehdr.e_phnum, proc->elf_ehdr.e_phoff);
  printf(WHITE "Program Headers:\n" NORMAL);
  printf(WHITE "  %-14s  %-16s  %-20s  %-16s\r\n", "Type", "Offset", "VirtAddr", "PhysAddr");
  printf("  %-14s  %-16s  %-20s  %-6s  %-6s\r\n", "", "FileSiz", "MemSiz", "Flags", "Align" NORMAL);
  for (size_t i = 0; i < proc->elf_ehdr.e_phnum; i++)
  {
    printf(
        WHITE "  %-14s\x1B[0m  0x%016lx  0x%016lx  0x%016lx\r\n  %-14s  0x%016lx  0x%016lx  %-7s 0x%-6lx\n",
        print_type_phdr(proc->elf_phdr[i].p_type), proc->elf_phdr[i].p_offset,
        proc->elf_phdr[i].p_vaddr, proc->elf_phdr[i].p_paddr, "", proc->elf_phdr[i].p_filesz, proc->elf_phdr[i].p_memsz,
        print_flag_phdr(proc->elf_phdr[i].p_flags), proc->elf_phdr[i].p_align);

    if (proc->elf_phdr[i].p_type == PT_INTERP)
    {
      if (is_printable(tmp + proc->elf_phdr[i].p_offset) == 0)
        printf("\t[Requesting program interpreter: %s]\n", tmp + proc->elf_phdr[i].p_offset);
    }
  }
  if (munmap(tmp, statbuff.st_size) == -1)
  {
    perror("munmap");
    return -1;
  }
  return 0;
}

char *print_type_phdr(long long c)
{
  switch (c)
  {
  case PT_NULL:
    return "PT_NULL";
  case PT_LOAD:
    return "PT_LOAD";
  case PT_DYNAMIC:
    return "PT_DYNAMIC";
  case PT_INTERP:
    return "PT_INTERP";
  case PT_NOTE:
    return "PT_NOTE";
  case PT_SHLIB:
    return "PT_SHLIB";
  case PT_PHDR:
    return "PT_PHDR";
  case PT_LOPROC:
    return "PT_LOPROC";
  case PT_HIPROC:
    return "PT_HIPROC";
  case PT_GNU_STACK:
    return "PT_GNU_STACK";
  case PT_TLS:
    return "PT_TLS";
  case PT_NUM:
    return "PT_NUM";
  case PT_GNU_EH_FRAME:
    return "PT_GNU_EH_FRAME";
  case PT_GNU_RELRO:
    return "PT_GNU_RELRO";
  case 0x6474e553:
    return "GNU_PROPERTY";
  default:
    return "unknown type";
  }
}

char *print_flag_phdr(uint32_t c)
{
  switch (c)
  {
  case PF_X:
    return "X";
  case PF_R:
    return "R";
  case PF_W:
    return "W";
  case PF_W | PF_X:
    return "W X";
  case PF_R | PF_X:
    return "R X";
  case PF_R | PF_W:
    return "R W";
  case PF_W | PF_R | PF_X:
    return "W R X";
  default:
    return " ";
  }
}

int info_sections(child_proc *proc)
{
  if ((proc->elf_ehdr.e_shoff == 0) || (proc->elf_ehdr.e_shnum == 0) || (proc->elf_ehdr.e_shentsize) == 0)
  {
    fprintf(stderr, "There are no sections in this file.\n");
    return 0;
  }
  struct stat statbuff = {0};
  if (fstat(proc->fd, &statbuff) == -1)
  {
    perror("fstat");
    return -1;
  }
  char *tmp = mmap(0, statbuff.st_size, PROT_READ, MAP_PRIVATE, proc->fd, 0);
  if (tmp == MAP_FAILED)
  {
    perror("mmap");
    return -1;
  }
  proc->elf_shdr = (Elf64_Shdr *)(tmp + proc->elf_ehdr.e_shoff);
  // get the string table index from the elf header and use elf_shdr to get
  // string table offset
  char *string_table = (proc->elf_ehdr.e_shstrndx != SHN_UNDEF) ? ((char *)(tmp + (proc->elf_shdr[proc->elf_ehdr.e_shstrndx].sh_offset))) : NULL;
  if (string_table == NULL)
  {
    munmap(tmp, statbuff.st_size);
    return -1;
  }
  printf(" There are %d section headers, starting at offset %lx:\n",
         proc->elf_ehdr.e_shnum, proc->elf_ehdr.e_shoff);
  printf(WHITE "\nSection header:\n" NORMAL);
  printf(WHITE "  %s %-18s %-18s %-19s %s\n", "[Nr]", "Name", "Type", "Address", "Offset" NORMAL);
  printf(WHITE " %-5s %-18s %-18s %-6s %-6s %-5s %-6s\n", "", "Size", "Entsize", "Flags", "Link", "Info", "Align" NORMAL);
  for (size_t i = 0; i < proc->elf_ehdr.e_shnum; i++)
  {
    printf(WHITE
           "  [%2ld]\x1B[0m %-18s %-18s 0x%016lx  0x%08lx\r\n %-5s 0x%016lx 0x%016lx ",
           i, string_table + proc->elf_shdr[i].sh_name, print_type_shdr(proc->elf_shdr[i].sh_type),
           proc->elf_shdr[i].sh_addr, proc->elf_shdr[i].sh_offset, "",
           proc->elf_shdr[i].sh_size, proc->elf_shdr[i].sh_entsize);
    print_flag_shdr(proc->elf_shdr[i].sh_flags);
    printf("      0x%x 0x%x 0x%lx", proc->elf_shdr[i].sh_link,
           proc->elf_shdr[i].sh_info, proc->elf_shdr[i].sh_addralign);
    printf("\n");
  }
  return 0;
}


char *print_type_shdr(uint32_t c) {
  switch (c) {
  case SHT_NULL:
    return "NULL";
  case SHT_PROGBITS:
    return "PROGBITS";
  case SHT_SYMTAB:
    return "SYMTAB";
  case SHT_STRTAB:
    return "STRTAB";
  case SHT_RELA:
    return "RELA";
  case SHT_HASH:
    return "HASH";
  case SHT_DYNAMIC:
    return "DYNAMIC";
  case SHT_NOTE:
    return "NOTE";
  case SHT_NOBITS:
    return "NOBITS";
  case SHT_REL:
    return "REL";
  case SHT_SHLIB:
    return "SHLIB";
  case SHT_DYNSYM:
    return "DYNSYM";
  case SHT_INIT_ARRAY:
    return "INIT_ARRAY";
  case SHT_FINI_ARRAY:
    return "FINI_ARRAY";
  case SHT_PREINIT_ARRAY:
    return "PREINIT_ARRAY";
  case SHT_GNU_HASH:
    return "GNU_HASH";
  case SHT_GROUP:
    return "GROUP";
  case SHT_SYMTAB_SHNDX:
    return "SYMTAB SECTION INDICES";
  case SHT_GNU_verdef:
    return "VERDEF";
  case SHT_GNU_verneed:
    return "VERNEED";
  case SHT_GNU_versym:
    return "VERSYM";
  case 0x6ffffff0:
    return "VERSYM";
  case 0x6ffffffc:
    return "VERDEF";
  case 0x7ffffffd:
    return "AUXILIARY";
  case 0x7fffffff:
    return "FILTER";
  case SHT_GNU_LIBLIST:
    return "GNU_LIBLIST";
  default:
    return "unknown type";
  }
}

void print_flag_shdr(uint64_t c) {
  if (c & SHF_WRITE)
    putchar('W');
  if (c & SHF_ALLOC)
    putchar('A');
  if (c & SHF_EXECINSTR)
    putchar('X');
  if (c & SHF_MERGE)
    putchar('M');
  if (c & SHF_STRINGS)
    putchar('S');
  if (c & SHF_INFO_LINK)
    putchar('I');
  if (c & SHF_LINK_ORDER)
    putchar('L');
  if (c & SHF_OS_NONCONFORMING)
    putchar('O');
  if (c & SHF_GROUP)
    putchar('G');
  if (c & SHF_TLS)
    putchar('T');
}


void print_symbols(Elf64_Ehdr header, Elf64_Shdr *shdr, int fd)
{
  (void)header;
  (void)shdr;
  (void)fd;
}

Elf64_Shdr *get_shdr(int fd, Elf64_Shdr *elf_shdr, Elf64_Ehdr elf_ehdr)
{
  // if ((elf_ehdr.e_shoff == 0) || (elf_ehdr.e_shnum == 0) || (elf_ehdr.e_shentsize) == 0)
  // {
  //   return NULL;
  // }
  struct stat statbuff = {0};
  if (fstat(fd, &statbuff) == -1)
  {
    perror("fstat");
    return NULL;
  }
  char *tmp = mmap(0, statbuff.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (tmp == MAP_FAILED)
  {
    perror("mmap");
    return NULL;
  }
  elf_shdr = (Elf64_Shdr *)(tmp + elf_ehdr.e_shoff);
  return elf_shdr;
}

Elf64_Phdr *get_phdr(int fd, Elf64_Phdr *elf_phdr, Elf64_Ehdr elf_ehdr)
{
  struct stat statbuff = {0};
  int err = fstat(fd, &statbuff);
  if (err == -1)
  {
    perror("fstat");
    return NULL;
  }

  char *tmp = mmap(0, statbuff.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (tmp == MAP_FAILED)
  {
    perror("mmap");
    return NULL;
  }
  elf_phdr = (Elf64_Phdr *)(tmp + elf_ehdr.e_phoff);
  return elf_phdr;
}
