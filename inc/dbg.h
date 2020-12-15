#ifndef DBG_H
#define DBG_H

#include <assert.h>
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
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct commandline {
    char *str;
    struct commandline *next;
} commandline;

unsigned int handle_addr(char *str);
char *command_input();
char *set_program_name(char *argv, char *buffer);
void insert_cmd(commandline **start, char *str);
void print_cmd(commandline *cmd);
void unimplemented(void);
int handle_cmd(char *cmd);

#endif