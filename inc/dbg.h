#ifndef	DBG_H 
#define DBG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <elf.h>
#include <sys/mman.h>

typedef struct h_cmd{
	char			*str;
	struct h_cmd	*next;
}h_cmd;


/*typedef struct h_cmd{
	char	*str;
	int (*handler)(void);
}h_cmd;
*/
typedef struct break_p{
	long long		addr;
	struct break_p	*next;
}break_p;

void child_process(char* prog);
void single_step(pid_t pid, struct user_regs_struct *regs);
void insert_cmd(h_cmd **start, char* str);
void print_cmd(h_cmd *cmd);
int handle_cmd(char *cmd);
void info_regs(struct user_regs_struct *regs, pid_t pid);
void cont_step(pid_t pid);
void trace_syscall(pid_t pid);
void step_syscall(pid_t pid, struct user_regs_struct *regs);
void add_break_point(break_p **start, long long int address);
void print_break_points(break_p *head);
unsigned int handle_addr(char *str);
void print_memory(pid_t pid);
int waitchild(pid_t pid);
unsigned long readfrom(pid_t pid, unsigned long address);
void set_ins(pid_t pid, unsigned long address, unsigned long instruction);
unsigned long long set_break_p(pid_t pid, unsigned long long address);

#endif
