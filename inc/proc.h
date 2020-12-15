#ifndef PROC_H
#define PROC_H

#include "breakpoint.h"
#include "proc.h"

typedef struct child_proc {
    char *command;
    Elf64_Ehdr header;
    Elf64_Shdr *shdr;
    int status;
    int fd;
    int running;
    pid_t pid;
    struct user_regs_struct regs;
} child_proc;

void print_memory(pid_t pid);
void trace_syscall(pid_t pid);
size_t get_address(pid_t pid);
void child_process(char *prog);
void info_regs(struct user_regs_struct *regs, pid_t pid);
void single_step(pid_t pid, struct user_regs_struct *regs);
void step_syscall(breakpoint **breakpoint_list, child_proc **proc);
void waitchild(child_proc **proc, breakpoint **breakpoint_list);
void continue_exec(child_proc **proc, breakpoint **breakpoint_list);
int handle_breakpoint(breakpoint **breakpoint_list, child_proc **proc);

#endif
