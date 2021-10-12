#include "regs.h"
#include "dbg.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>

size_t get_rip(pid_t pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1)
    {
        perror("ptrace_getregs");
        return -1;
    }
    return regs->rip;
}

void dump_registers(pid_t pid, struct user_regs_struct regs)
{
    printf("\n\x1B[37;1mPrint Registers:\x1B[0m\n\n");
    printf(
        "\x1B[37;1mRAX: \x1B[0m0x%llx%-3s\x1B[37;1mRBX: \x1B[0m0x%llx%-3s"
        "\x1B[37;1mRCX: \x1B[0m0x%llx%-3s\x1B[37;1mRDX: \x1B[0m0x%llx\n",
        regs.rax, "", regs.rbx, "", regs.rcx, "", regs.rdx);
    printf(
        "\x1B[37;1mR15: \x1B[0m0x%llx%-3s\x1B[37;1mR14: \x1B[0m0x%llx%-3s"
        "\x1B[37;1mR13: \x1B[0m0x%llx%-3s\x1B[37;1mR12: \x1B[0m0x%llx\n",
        regs.r15, "", regs.r14, "", regs.r13, "", regs.r12);
    printf(
        "\x1B[37;1mR11: \x1B[0m0x%llx%-3s\x1B[37;1mR10: \x1B[0m0x%llx%-3s"
        "\x1B[37;1mR9: \x1B[0m0x%llx%-3s\x1B[37;1mR8: \x1B[0m0x%llx\n",
        regs.r11, "", regs.r10, "", regs.r9, "", regs.r8);
    printf(
        "\x1B[37;1mRSP: \x1B[0m0x%llx%-3s\x1B[37;1mRBP: \x1B[0m0x%llx%-3s"
        "\x1B[37;1mRSI: \x1B[0m0x%llx%-3s\x1B[37;1mRDI: \x1B[0m0x%llx\n",
        regs.rsp, "", regs.rbp, "", regs.rsi, "", regs.rdi);
    printf(
        "\x1B[37;1mRIP: \x1B[0m0x%llx%-3s\x1B[37;1mCS:  \x1B[0m0x%llx%-3s"
        "\x1B[37;1mEFLAGS: \x1B[0m0x%llx\n",
        regs.rip, "", regs.cs, "", regs.eflags);
    printf(
        "\x1B[37;1mSS:  \x1B[0m0x%llx%-3s\x1B[37;1mDS:  \x1B[0m0x%llx%-3s"
        "\x1B[37;1mES:  \x1B[0m0x%llx%-3s\x1B[37;1mFS:  \x1B[0m0x%llx%-3s\x1B[37;1mGS:  \x1B[0m0x%llx\n",
        regs.ss, "", regs.ds, "", regs.es, "", regs.fs, "", regs.gs);

    printf(WHITE "\nPrint Stack:\x1B[0m\n\n");
    size_t value = ptrace(PTRACE_PEEKDATA, pid, regs.rsp, NULL);
    printf(WHITE "0x%llx | \x1B[0m0x%lx\n", regs.rsp, value);
    for (int i = 1; i < 10; i++)
    {
        value = ptrace(PTRACE_PEEKDATA, pid, regs.rsp + i * 8, NULL);
        printf(WHITE "0x%llx | \x1B[0m0x%lx\n", regs.rsp + i * 8, value);
    }
}

char *get_regs(char *command)
{
    char *regs_name = (char *)malloc((sizeof(char) * 3) + 1);
    if(regs_name == NULL){
        perror("malloc");
        return NULL;
    }
    memset(regs_name, 0, (sizeof(char) * 3) + 1);
    while (*command)
    {
        if (*command == '$')
        {
            strncpy(regs_name, ++command, (sizeof(char) * 3));
            return regs_name;
        }
        command++;
    }
    return NULL;
}

int search_regs(char *command)
{
    char *regs[] = {"r15", "r14",      // 0, 1
                    "r13", "r12",      // 2, 3
                    "rbp", "rbx",      // 4, 5
                    "r11", "r10",      // 6, 7
                    "r9", "r8",        // 8, 9
                    "rax", "rcx",      // 10, 11
                    "rdx", "rsi",      // 12, 13
                    "rdi", "rip",      // 14, 15
                    "cs", "rsp",       // 16, 17
                    "ss", "ds",        // 18, 19
                    "es", "fs", "gs"}; // 20, 21, 22
    for (int i = 0; i < 23; i++)
    {
        if (string_compare(regs[i], command, strlen(regs[i])) == 0)
        {
            return i;
        }
    }
    return -1;
}

size_t get_value(char *command)
{
    char *value = malloc((sizeof(char) * 1) + 1);
    memset(value, 0, (sizeof(value) / sizeof(*value)));
    for(int i = 0; command[i] != '\0'; i++)
    {
        if (command[i] == '"')
        {
            for (size_t j = 0; value[j] != '\0' || command[i] != '\0'; j++)
            {
                value[j] = command[++i];
                value = realloc(value, strlen(value) + 1);
            }
            value[strlen(value)-1] = '\0';
            return str_to_hex(value);
        }
    }
    return strtoul(++command, NULL, 16);
}

int set_register(ssize_t value, int index, child_proc *proc){
    enum regs { R15 = 0, R14, R13, R12, RBP, RBX, R11, R10, R9, R8, RAX, RCX, RDX, RSI, RDI, RIP, CS, RSP, SS, DS, ES, FS, GS };
    // sorry not sorry maybe later i will try another solution
    // this code is generated by python script
    switch (index)
    {
        case R15:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.r15 = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case R14:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.r14 = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case R13:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.r13 = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case R12:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.r12 = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case RBP:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.rbp = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case RBX:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.rbx = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case R11:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.r11 = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case R10:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.r10 = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case R9:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.r9 = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case R8:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.r8 = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case RAX:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.rax = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case RCX:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.rcx = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case RDX:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.rdx = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case RSI:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.rsi = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case RDI:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.rdi = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case RIP:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.rip = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case CS:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.cs = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case RSP:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.rsp = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case SS:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.ss = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case DS:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.ds = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case ES:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.es = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case FS:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.fs = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        case GS:
        {
            if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            proc->regs.gs = value;
            if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &(proc->regs)) == -1)
            {
                perror("ptrace_regs");
                return -1;
            }
            break;
        }
        default:
        {
            return -1;
        }
    }
    return 0;
}