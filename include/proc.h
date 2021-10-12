#ifndef PROC_H
#define PROC_H

#include <elf.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/types.h>

#define RUNNING 0
#define NOT_RUNNING 1

typedef struct child_proc {
    int fd;
    pid_t pid;
    int status;
    char *command;
    Elf64_Ehdr elf_ehdr;
    Elf64_Shdr *elf_shdr;
    Elf64_Phdr *elf_phdr;
    struct user_regs_struct regs;
} child_proc;

int jump_start(child_proc *, size_t );
int prepare_tracee(child_proc *, char **);
void proc_cmdline(pid_t );
void proc_maps(pid_t );

#endif

