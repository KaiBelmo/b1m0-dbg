#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <elf.h>
#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>


#define ENABLED 1
#define DISABLED 0

typedef struct breakpoint {
    int index;
    int status;
    size_t old_opcode;
    size_t new_opcode;
    size_t break_address;
    struct breakpoint *next;
} breakpoint;

long unsigned set_address(char *buffer);
void print_breakpoint_list(breakpoint *breakpoint_list);
void enable_breakpoint(pid_t pid, breakpoint **break_point);
void disable_breakpoint(pid_t pid, breakpoint **break_point);
void insert_in_breakpoint_list(struct breakpoint **start, long int address);
void set_breakpoint_at_address(pid_t pid, size_t break_address, breakpoint** breakpoint_list);

#endif