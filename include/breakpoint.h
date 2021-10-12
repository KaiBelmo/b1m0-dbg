#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include "proc.h"

#define ENABLED 1
#define DISABLED 0

typedef struct breakpoint {
    int status;
    size_t old_opcode;
    size_t new_opcode;
    size_t break_address;
    struct breakpoint *next;
} breakpoint;

void print_breakpoint_list(breakpoint *);
int wait_tracee(child_proc *, breakpoint *);
breakpoint *insert_breakpoint_list(breakpoint *, breakpoint *);
breakpoint *set_breakpoint(child_proc *, breakpoint* , size_t );
breakpoint *enable_breakpoint(breakpoint *, child_proc *, size_t );

#endif