#include "proc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include "breakpoint.h"
#include <sys/ptrace.h>
#include <bits/types.h>

breakpoint *set_breakpoint(child_proc *proc, breakpoint* breakpoint_list, size_t address){
    breakpoint *tmp = (breakpoint *)malloc(sizeof(breakpoint));
    if (tmp == NULL)
    {
        perror("malloc");
        return NULL;
    }
    tmp = enable_breakpoint(tmp, proc, address);
    if (tmp == NULL)
    {
        free(tmp);
        return NULL;
    }
    breakpoint_list = insert_breakpoint_list(breakpoint_list, tmp);
    return breakpoint_list;
}

breakpoint *enable_breakpoint(breakpoint *tmp, child_proc *proc, size_t break_address){
    tmp->break_address = break_address;
    tmp->next = NULL;
    tmp->old_opcode =  ptrace(PTRACE_PEEKDATA, proc->pid, tmp->break_address, NULL);
    if (tmp->old_opcode == -1)
    {
        perror("ptrace_peekdata");
        return NULL;
    }
    tmp->new_opcode = ((tmp->old_opcode & ~0xff) | 0xcc);
    int err = ptrace(PTRACE_POKEDATA, proc->pid, tmp->break_address, tmp->new_opcode);
    if(err == -1){
        perror("ptrace_pokedata");
        return NULL;
    }
    tmp->status = ENABLED;
    return tmp;
}

breakpoint *insert_breakpoint_list(breakpoint *breakpoint_list, breakpoint *new_node){
    breakpoint *tmp = breakpoint_list;
    if (breakpoint_list == NULL)
    {
        breakpoint_list = new_node;
        return breakpoint_list;
    }
    while (tmp->next != NULL)
    {
        tmp = tmp->next;
    }
    tmp->next = new_node;    
    return breakpoint_list;
}

void print_breakpoint_list(breakpoint *breakpoint_list){
    if(breakpoint_list == NULL)
    {
        printf("No breakpoints set yet");
        return;
    }
    while (breakpoint_list != NULL)
    {
        printf("address %lx | oldop %lx | newop %lx | status %s\n", breakpoint_list->break_address, breakpoint_list->old_opcode, breakpoint_list->new_opcode, (breakpoint_list->status == ENABLED) ? "enabled" : "disabled");
        breakpoint_list = breakpoint_list->next;
    }
}

int handle_breakpoint(child_proc *proc, breakpoint *breakpoint_list){
    size_t rip_address = 0;
    int err = 0;

    err = ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs));
    if(err == -1){
        perror("ptrace_getregs");
        return -1;
    }
    rip_address = proc->regs.rip;
    while (breakpoint_list != NULL)
    {
        if (breakpoint_list->break_address == (rip_address - 1))
        {
            // disable breakpoint
            err = ptrace(PTRACE_POKEDATA, proc->pid, breakpoint_list->break_address, breakpoint_list->old_opcode);
            if (err == -1){
                perror("ptrace_pokedata");
                return -1;
            }
            proc->regs.rip -= 1;
            err = ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs));
            if (err == -1){
                perror("ptrace_setregs");
                return -1;
            }
            return 0;
        }
        breakpoint_list = breakpoint_list->next;
    }

    return -1;
}

int wait_tracee(child_proc *proc, breakpoint *breakpoint_list)
{
    int wstatus = 0;
    siginfo_t siginfo = {0};
    if (waitpid(proc->pid, &wstatus, 0) == -1)
    {
        perror("wait");
        return -1;
    }
    if (WIFSTOPPED(wstatus) == true)
    {
        if (ptrace(PTRACE_GETSIGINFO, proc->pid, NULL, &siginfo) == -1){
            perror("ptrace_getsiginfo");
            return -1;
        }
		switch(siginfo.si_signo)
		{
			case SIGSEGV:
			{
				switch(siginfo.si_code)
				{
					case SEGV_MAPERR:
						printf("SIGSEGV: Address not mapped.\n");
						break;
					case SEGV_ACCERR:
						printf("SIGSEGV: Invalid permissions.\n");
						break;
					default:
						printf("SIGSEGV: unknown code %d\n", siginfo.si_code);
						break;
				}
				proc->status = NOT_RUNNING;	
				break;
			}
			case SIGTRAP:
			{
                //printf("signal code = %x\n", siginfo.si_code);
				switch(siginfo.si_code)
				{
                    case 0x85: // no idea wtf is this, i discovered it through debugging
                               // but it works so yay
                    {
                        break;
                    }
                    case 0x80: // SI_KERNEL, sent by the kernel
                    case 1: // TRAP_BRKPT, for breakpoints
                    {
                        if (handle_breakpoint(proc, breakpoint_list) == 0)
                        {
                            break;
                        }
                    }
					case 2: // TRAP_TRACE, this will be set in case of single stepping
					{
						break;
					}
					default:
                    {
						printf("SIGTRAP: %s", strsignal(siginfo.si_signo));
                        proc->status = NOT_RUNNING;
                        break;
                    }
				}
			}
			case SIGFPE:
			{
				break;
			}
            case SIGCHLD:
			{
				break;
			}case SIGBUS:
			{
				break;
			}
			default:
				printf("(Process %d interrupted by signal %s)", proc->pid, strsignal(siginfo.si_signo));
		
		}
        // TODO: for single stepping to skip breakpoints
    }
    else if (WIFEXITED(wstatus) == true)
    {
        printf("(Process %d exited with code %d)\n", proc->pid,
               WEXITSTATUS(wstatus));
        proc->status = NOT_RUNNING;
    }
    else if (WTERMSIG(wstatus) == true)
    {
        printf("Process %d terminated by signal %s)\n", proc->pid,
               strsignal(WTERMSIG(wstatus)));
        proc->status = NOT_RUNNING;
    }
    return proc->status;
}
