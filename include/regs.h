#ifndef REGS_H
#define REGS_H

#include <sys/user.h>
#include <unistd.h>
#include "proc.h"

char *get_regs(char *);
int search_regs(char *);
size_t get_value(char *);
size_t get_rip(pid_t , struct user_regs_struct *);
void dump_registers(pid_t , struct user_regs_struct );
int set_register(ssize_t , int , child_proc *);

#endif