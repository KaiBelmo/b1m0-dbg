#ifndef DBG_H
#define DBG_H

#include "proc.h"
#include "breakpoint.h"

#define NORMAL "\x1B[0m"
#define RED "\x1B[31;1m"
#define WHITE "\x1B[37;1m"

int usage(char** );
int string_compare(char *, char *, size_t);
int is_printable(char *);
void unimplemented(void);
char *get_userinput(void);
ssize_t str_to_hex(const char *);
int single_step(child_proc *, int *, breakpoint *);
int step_out(child_proc *, int *, breakpoint *, struct user_regs_struct *);
int continue_execution(child_proc *, int *, breakpoint *);
int check_file_permissions(char *);
size_t set_address(char *);
#endif

