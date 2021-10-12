#include "dbg.h"
#include "proc.h"
#include "regs.h"
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "syscall.h"
#include "checksec.h"
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h>
#include "breakpoint.h"
#include "elf_parser.h"
#include <sys/ptrace.h>
#include <readline/history.h>

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        return usage(argv);
    }
    child_proc *proc = (child_proc *)malloc(sizeof(child_proc));
    breakpoint *breakpoint_list = (breakpoint *)malloc(sizeof(breakpoint));
    int wstatus = 0;
    if (proc == NULL || breakpoint_list == NULL)
    {
        perror("malloc");
        return errno;
    }
    memset(proc, 0, sizeof(child_proc));
    memset(breakpoint_list, 0, sizeof(breakpoint));

    if (check_file_permissions(argv[1]))
    {
        free(proc);
        return -1;
    }
    proc->fd = open(argv[1], O_RDONLY | O_SYNC);
    if (proc->fd == -1)
    {
        free(proc);
        perror("open");
        return errno;
    }
    if (check_elf_file(proc->fd, &(proc->elf_ehdr)) == -1)
    {
        close(proc->fd);
        free(proc);
        return -1;
    }
    printf("Reading info from executable\n");

    proc->pid = fork();
    if (proc->pid == -1)
    {
        perror("fork");
        close(proc->fd);
        free(proc);
        return errno;
    }
    if (proc->pid == 0)
    {
        if (prepare_tracee(proc, argv) == -1)
        {
            close(proc->fd);
            free(proc);
            return errno;
        }
    }
    else if (proc->pid >= 1)
    {
        printf("Attaching to pid %d\n", proc->pid);
        if (waitpid(proc->pid, &wstatus, 0) == -1)
        {
            perror("wait");
            return errno;
        }
        ptrace(PTRACE_SETOPTIONS, proc->pid, 0,
               PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK);

        while (proc->status == RUNNING)
        {
            printf(RED "\n[B1MO:0x%08lx]>" NORMAL, get_rip(proc->pid, &(proc->regs)));
            proc->command = get_userinput();
            if (proc->command == NULL)
            {
                break;
            }
            if (string_compare("info header", proc->command, strlen("info header")) == 0)
            {
                info_header(proc);
            }
            else if (string_compare("info segments", proc->command, strlen("info segments")) == 0)
            {
                if (info_segements(proc) == -1){
                    break;
                }
            }
            else if (string_compare("info sections", proc->command, strlen("info sections")) == 0)
            {
                if (info_sections(proc) == -1){
                    break;
                }
            }
            else if (string_compare("info symbols", proc->command, strlen("info symbols")) == 0)
            {
                unimplemented();
            }
            else if (string_compare("single step", proc->command, strlen("single step")) == 0 || string_compare("ss", proc->command, strlen("ss")) == 0)
            {
                if (single_step(proc, &(proc->status), breakpoint_list) == -1){
                    continue;
                }
            }
            else if (string_compare("trace sys", proc->command, strlen("trace sys")) == 0)
            {
                if (trace_syscalls(proc, &(proc->status)) == -1){
                    break;
                }
            }
            else if (string_compare("step syscall", proc->command, strlen("step syscall")) == 0)
            {
                if (step_syscall(proc, &(proc->status), breakpoint_list) == -1){
                    continue;
                }
            }
			else if (string_compare("continue", proc->command, strlen("continue")) == 0)
            {
				if(continue_execution(proc, &(proc->status), breakpoint_list) == -1){
					break;
				}
            }
            else if (string_compare("break *", proc->command, strlen("break *")) == 0)
            {
                size_t break_address = set_address(proc->command);
                breakpoint_list = set_breakpoint(proc, breakpoint_list, break_address);
                if (breakpoint_list == NULL){
                    continue;
                }
            }
            else if (string_compare("lsb", proc->command, strlen("lsb")) == 0)
            {
                print_breakpoint_list(breakpoint_list);
            }
            else if (string_compare("regs", proc->command, strlen("regs")) == 0)
            {
                dump_registers(proc->pid, proc->regs);
            }
            else if ((string_compare("quit", proc->command, strlen("quit")) == 0) || (string_compare("q", proc->command, strlen("q")) == 0))
            {
                ptrace(PTRACE_KILL, proc->pid, 0, 0);
                break;
            }
            else if (string_compare("set $", proc->command, strlen("set $")) == 0)
            {
               char *regs_name = get_regs(proc->command);
               if(regs_name == NULL){
                   continue;
               }
               ssize_t value = get_value(strchr(proc->command, '='));
               int i = search_regs(regs_name);
               if(i == -1){
                   printf("%s not a valid register", regs_name);
                   free(regs_name);
                   continue;
               }
               if(set_register(value, i, proc) == -1){
                   free(regs_name);
                   continue;
               }
            }
            else if (string_compare("_start", proc->command, strlen("_start")) == 0)
            {
                jump_start(proc, proc->elf_ehdr.e_entry);
            }
            else if (string_compare("dump *", proc->command, strlen("dump *")) == 0)
            {
                size_t address = set_address(proc->command);
                printf("%lx", address);
                /* hex dump at specific adress */
                unimplemented();
            }
            else if (string_compare("checksec", proc->command, strlen("checksec")) == 0)
            {
                proc->elf_shdr = get_shdr(proc->fd, proc->elf_shdr, proc->elf_ehdr);
                if(proc->elf_shdr == NULL){
                    continue;
                }
                proc->elf_phdr = get_phdr(proc->fd, proc->elf_phdr, proc->elf_ehdr);
                if(proc->elf_phdr == NULL){
                    continue;
                }
                check_relro(proc->elf_phdr, proc->elf_ehdr.e_phnum);
                check_NX(proc->elf_phdr, proc->elf_ehdr.e_phnum);
                check_aslr(proc->elf_ehdr);
                check_stack_canary();
            }
            else if (string_compare("finish", proc->command, strlen("finish")) == 0)
            {
                step_out(proc, &(proc->status), breakpoint_list, &(proc->regs));
            }
            else if (string_compare("info proc cmdline", proc->command, strlen("info proc cmdline")) == 0)
            {
                proc_cmdline(proc->pid);
            }
            else if (string_compare("info proc maps", proc->command, strlen("info proc maps")) == 0)
            {
                proc_maps(proc->pid);
            }
            else
            {
                printf("unkown command");
            }

            add_history(proc->command);
            free(proc->command);
        }
    }
    close(proc->fd);
    free(proc);
    return 0;
}

