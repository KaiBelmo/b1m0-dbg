#include "proc.h"
#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>

int prepare_tracee(child_proc *proc, char *argv[])
{
    if (ptrace(PTRACE_TRACEME, proc->fd, NULL, NULL) == -1)
    {
        perror("ptrace_traceme");
        return -1;
    }
    execv(argv[1], argv+1);
}

int jump_start(child_proc *proc, size_t start_address)
{
    int status = 0;
    size_t oldopcode = ptrace(PTRACE_PEEKDATA, proc->pid, start_address, NULL);
    if (oldopcode == -1)
    {
        perror("ptrace_peekdata");
        return -1;
    }
    size_t newopcode = ((oldopcode & ~0xff) | 0xcc);

    if (ptrace(PTRACE_POKEDATA, proc->pid, start_address, newopcode) == -1)
    {
        perror("ptrace_pokedata");
        return -1;
    }
    if (ptrace(PTRACE_CONT, proc->pid, NULL, NULL) == -1)
    {
        perror("ptrace_cont");
        return -1;
    }
    waitpid(proc->pid, &status, 0);
    if (WIFSTOPPED(status))
    {
        if (ptrace(PTRACE_POKEDATA, proc->pid, start_address, oldopcode) == -1)
        {
            perror("ptrace_pokedata");
        }
        if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
        {
            perror("ptrace_regs");
            return -1;
        }
        proc->regs.rip -= 1;
        if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
        {
            perror("ptrace_regs");
            return -1;
        }
    }
    else
    {
        perror("wait");
    }
    return 0;
}

void proc_cmdline(pid_t pid){
    char path[25];
    FILE *fp;
    char c;
    sprintf(path, "/proc/%d/cmdline", pid);
    fp = fopen(path, "r");
    if (fp) {
        while ((c = getc(fp)) != EOF) putchar(c);
        fclose(fp);
    }
}

void proc_maps(pid_t pid){
    char path[25];
    FILE *fp;
    char c;
    sprintf(path, "/proc/%d/maps", pid);
    fp = fopen(path, "r");
    if (fp) {
        while ((c = getc(fp)) != EOF) putchar(c);
        fclose(fp);
    }
}

