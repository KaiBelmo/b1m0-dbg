
#include "breakpoint.h"
#include "dbg.h"
#include "elf_parser.h"
#include "proc.h"

breakpoint *breakpoint_list = NULL;
commandline *commandline_list = NULL;

int main(int argc, char **argv) {
    child_proc *proc = (child_proc *)malloc(sizeof(child_proc));
    uint64_t break_address;
    int wstatus;

    if (argc != 2) {
        f_usage(argv[0]);
        return -1;
    }    
    if (proc == NULL) {
        perror("malloc");
        return 1;
    }
    memset(proc, 0, sizeof(child_proc));
    proc->fd = open(argv[1], O_RDONLY | O_SYNC);
    proc->command = (char *)malloc(sizeof(char) * 14);

    if (f_check(argv[1])) {
        return -1;
    }
    if (!(f_check_elf(proc->fd, (&proc->header)))) {
        printf("Reading info from executable\n");
    } else {
        printf("\t Check your executable!\n");
        return -1;
    }

    proc->pid = fork();
    if (proc->pid == -1) {
        perror("fork");
        return -1;
    }
    if (proc->pid == 0) {
        child_process(argv[1]);
    } else if (proc->pid >= 1) {
        usleep(200000);
        printf("Attaching to pid %d\n", proc->pid);
        wait(&wstatus);
        while (1) {
            printf(RED "[B1MO:0x%llx]>" NORMAL, proc->regs.rip);
            proc->command = command_input();
            insert_cmd(&commandline_list, proc->command);
            fflush(stdin);
            switch (handle_cmd(proc->command)) {
                case 0:
                    single_step(proc->pid, (&proc->regs));
                    break;
                case 1:
                    print_cmd(commandline_list);
                    break;
                case 2:
                    // info header / info section / info symbols
                    if (strcmp(proc->command, "info file") == 0) {
                        info_header(proc->header);
                        break;
                    } else if (strcmp(proc->command, "info section") == 0) {
                        print_section(proc->header, proc->shdr, proc->fd);
                        break;
                    } else if (strcmp(proc->command, "info symbols") == 0) {
                        //print_symbols(proc->header, proc->shdr, proc->fd);
                        unimplemented();
                        break;
                    }
                    break;
                case 3:
                    // uwu
                    ptrace(PTRACE_KILL, proc->pid, NULL, NULL);
                    goto EXIT;
                    break;
                case 4:
                    info_regs((&proc->regs), proc->pid);
                    break;
                case 5:
                    continue_exec(&proc, &breakpoint_list);
                    if (proc->running ==  1){
                        goto EXIT;
                    }   
                    break;
                case 6:
                    trace_syscall(proc->pid);
                    goto EXIT;
                case 7:
                    step_syscall(&breakpoint_list, &proc);
                    break;
                case 8:
                    if ((break_address = set_address(proc->command)) == 1) {
                        printf(WHITE "Check your input\n" NORMAL);
                        break;
                    }
                    set_breakpoint_at_address(proc->pid, break_address, &breakpoint_list);
                    break;
                case 9:
		    print_breakpoint_list(breakpoint_list);
                    break;
                case 10:
                    print_memory(proc->pid);
                    break;
                default:
                    printf(WHITE"input:\x1B[0m %s command not found\n", proc->command);
            }
        }
    } 
EXIT:
    return 0;
}
