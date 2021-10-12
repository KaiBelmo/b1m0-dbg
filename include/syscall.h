#ifndef SYSCALL_H
#define SYSCALL_H

#include "proc.h"
#include "breakpoint.h"

int trace_syscalls(child_proc *, int *);
int step_syscall(child_proc *, int *, breakpoint *);

#endif