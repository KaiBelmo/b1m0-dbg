#include "breakpoint.h"
#include "proc.h"
#include "dbg.h"
#include "elf_parser.h"

static char *syscall_names[314] = {"read","write","open","close","stat","fstat","lstat","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn","ioctl","pread64","pwrite64","readv","writev","access","pipe","select","sched_yield","mremap","msync","mincore","madvise","shmget","shmat","shmctl","dup","dup2","pause","nanosleep","getitimer","alarm","setitimer","getpid","sendfile","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg","shutdown","bind","listen","getsockname","getpeername","socketpair","setsockopt","getsockopt","clone","fork","vfork","execve","exit","wait4","kill","uname","semget","semop","semctl","shmdt","msgget","msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate","ftruncate","getdents","getcwd","chdir","fchdir","rename","mkdir","rmdir","creat","link","unlink","symlink","readlink","chmod","fchmod","chown","fchown","lchown","umask","gettimeofday","getrlimit","getrusage","sysinfo","times","ptrace","getuid","syslog","getgid","setuid","setgid","geteuid","getegid","setpgid","getppid","getpgrp","setsid","setreuid","setregid","getgroups","setgroups","setresuid","getresuid","setresgid","getresgid","getpgid","setfsuid","setfsgid","getsid","capget","capset","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend","sigaltstack","utime","mknod","uselib","personality","ustat","statfs","fstatfs","sysfs","getpriority","setpriority","sched_setparam","sched_getparam","sched_setscheduler","sched_getscheduler","sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval","mlock","munlock","mlockall","munlockall","vhangup","modify_ldt","pivot_root","_sysctl","prctl","arch_prctl","adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount","umount2","swapon","swapoff","reboot","sethostname","setdomainname","iopl","ioperm","create_module","init_module","delete_module","get_kernel_syms","query_module","quotactl","nfsservctl","getpmsg","putpmsg","afs_syscall","tuxcall","security","gettid","readahead","setxattr","lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr","removexattr","lremovexattr","fremovexattr","tkill","time","futex","sched_setaffinity","sched_getaffinity","set_thread_area","io_setup","io_destroy","io_getevents","io_submit","io_cancel","get_thread_area","lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old","remap_file_pages","getdents64","set_tid_address","restart_syscall","semtimedop","fadvise64","timer_create","timer_settime","timer_gettime","timer_getoverrun","timer_delete","clock_settime","clock_gettime","clock_getres","clock_nanosleep","exit_group","epoll_wait","epoll_ctl","tgkill","utimes","vserver","mbind","set_mempolicy","get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive","mq_notify","mq_getsetattr","kexec_load","waitid","add_key","request_key","keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch","migrate_pages","openat","mkdirat","mknodat","fchownat","futimesat","newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat","fchmodat","faccessat","pselect6","ppoll","unshare","set_robust_list","get_robust_list","splice","tee","sync_file_range","vmsplice","move_pages","utimensat","epoll_pwait","signalfd","timerfd_create","eventfd","fallocate","timerfd_settime","timerfd_gettime","accept4","signalfd4","eventfd2","epoll_create1","dup3","pipe2","inotify_init1","preadv","pwritev","rt_tgsigqueueinfo","perf_event_open","recvmmsg","fanotify_init","fanotify_mark","prlimit64","name_to_handle_at","open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns","getcpu","process_vm_readv","process_vm_writev","kcmp","finit_module"};

void child_process(char *prog) {
    // Allow tracing of this process
    if (ptrace(PTRACE_TRACEME, NULL, NULL, NULL) < 0) {
        perror("ptrace");
        return;
    }
    // Replace this process's image with the given program
    execl(prog, prog, NULL);
}

int handle_breakpoint(breakpoint **breakpoint_list, child_proc **proc){
    int return_value = 1;
    size_t address = get_address((*proc)->pid);        
    ptrace(PTRACE_GETREGS, (*proc)->pid, NULL, &(*proc)->regs);
    while ((*breakpoint_list) != NULL){
        if ((*breakpoint_list)->break_address == (address - 1)){
            if (ptrace(PTRACE_POKEDATA, (*proc)->pid, (*breakpoint_list)->break_address, (*breakpoint_list)->old_opcode) != 0){
                perror("ptrace");
            }
            (*proc)->regs.rip = (*proc)->regs.rip - 1;
            if(ptrace(PTRACE_SETREGS, (*proc)->pid, NULL, &(*proc)->regs) != 0){
                perror("ptrace");
            }
            return_value = 0;
        }
        (*breakpoint_list) = (*breakpoint_list)->next;
    }
    return return_value;
}
void waitchild(child_proc **proc, breakpoint **breakpoint_list) {
    int status;

    waitpid((*proc)->pid, &status, 0);  // to listen for signals which are sent to the debugee
    if (WIFSTOPPED(status)) {  // returns true if the child (*proc)ess was stopped
                               // by delivery of a signal;
        if (handle_breakpoint(breakpoint_list, proc) == 0){
            return;
        }    
        if (WSTOPSIG(status)){  // returns the number of the signal which caused the child to stop;
            printf("(Process %d interrupted by signal %s)\n", (*proc)->pid, strsignal(WSTOPSIG(status)));
            (*proc)->running = 1;
            return;
        }
    } else if (WIFEXITED(status)) {  // returns true if the child terminated normally, exp: exit(0);
        printf("(Process %d exited with code %d)\n", (*proc)->pid, WEXITSTATUS(status));   // returns the exit status of the child;
        (*proc)->running = 1;
    } else if (WIFSIGNALED(status)) {  // returns true if the child process was terminated by a signal;
        printf("(Process %d terminated by signal %s)\n", (*proc)->pid, strsignal(WTERMSIG(status)));  // returns the number of the signal that caused
        (*proc)->running = 1;             // the child process to terminate;
    }
    return;
}

size_t get_address(pid_t pid){
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	return regs.rip;
}

void single_step(pid_t pid, struct user_regs_struct *regs) {
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    waitpid(pid, 0, 0);
    ptrace(PTRACE_GETREGS, pid, 0, regs);
}

void print_memory(pid_t pid) {
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

void continue_exec(child_proc **proc, breakpoint **breakpoint_list) {
    ptrace(PTRACE_CONT, (*proc)->pid, NULL, NULL);
    waitchild(proc, breakpoint_list);
    ptrace(PTRACE_GETREGS, (*proc)->pid, NULL, &(*proc)->regs);
}

void info_regs(struct user_regs_struct *regs, pid_t pid) {
    printf("\n\x1B[37;1mPrint Registers:\x1B[0m\n\n");
    printf(
        "\x1B[37;1mRAX: \x1B[0m0x%llx \x1B[37;1mRBX: \x1B[0m0x%llx "
        "\x1B[37;1mRCX: \x1B[0m0x%llx \x1B[37;1mRDX: \x1B[0m0x%llx\n",
        regs->rax, regs->rbx, regs->rcx, regs->rdx);
    printf(
        "\x1B[37;1mR15: \x1B[0m0x%llx \x1B[37;1mR14: \x1B[0m0x%llx "
        "\x1B[37;1mR13: \x1B[0m0x%llx \x1B[37;1mR12: \x1B[0m0x%llx\n",
        regs->r15, regs->r14, regs->r13, regs->r12);
    printf(
        "\x1B[37;1mR11: \x1B[0m0x%llx \x1B[37;1mR10: \x1B[0m0x%llx "
        "\x1B[37;1mR9: "
        " \x1B[0m0x%llx \x1B[37;1mR8:  \x1B[0m0x%llx\n",
        regs->r11, regs->r10, regs->r9, regs->r8);
    printf(
        "\x1B[37;1mRSP: \x1B[0m0x%llx \x1B[37;1mRBP: \x1B[0m0x%llx "
        "\x1B[37;1mRSI: \x1B[0m0x%llx \x1B[37;1mRDI: \x1B[0m0x%llx\n",
        regs->rsp, regs->rbp, regs->rsi, regs->rdi);
    printf(
        "\x1B[37;1mRIP: \x1B[0m0x%llx \x1B[37;1mCS:  \x1B[0m0x%llx "
        "\x1B[37;1mEFLAGS:\x1B[0m0x%llx\n",
        regs->rip, regs->cs, regs->eflags);
    printf(
        "\x1B[37;1mSS:  \x1B[0m0x%llx \x1B[37;1mDS:  \x1B[0m0x%llx "
        "\x1B[37;1mES: "
        " \x1B[0m0x%llx \x1B[37;1mFS:  \x1B[0m0x%llx \x1B[37;1mGS:  "
        "\x1B[0m0x%llx\n",
        regs->ss, regs->ds, regs->es, regs->fs, regs->gs);

    printf(WHITE "Print Stack:\x1B[0m\n\n");
    long long value = 0;
    value = ptrace(PTRACE_PEEKDATA, pid, regs->rsp, NULL);
    printf(WHITE "0x%llx | \x1B[0m0x%llx\n", regs->rsp, value);
    for (int i = 1; i < 10; i++) {
        value = ptrace(PTRACE_PEEKDATA, pid, regs->rsp + i * 8, NULL);
        printf(WHITE "0x%llx | \x1B[0m0x%llx\n", regs->rsp + i * 8, value);
    }
}

void trace_syscall(pid_t pid) {
    int status;
    int syscall_rax;
    while (!WIFEXITED(status)) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        wait(&status);
        syscall_rax = regs.orig_rax;
        printf(WHITE"%s\x1B[0m(0x%08llx, 0x%08llx, 0x%08llx, 0x%08llx);\n", 
                            syscall_names[syscall_rax], regs.rdi, regs.rsi, regs.rdx, regs.r10);
    }
    printf("Process %d exited with code %d\n", pid, WEXITSTATUS(status));
}

void step_syscall(breakpoint **breakpoint_list, child_proc **proc) { //underdevelopment
    int status;
    ptrace(PTRACE_SYSCALL, (*proc)->pid, 0, 0);
    waitchild(proc, breakpoint_list);
    ptrace(PTRACE_GETREGS, (*proc)->pid, 0, &(*proc)->regs);
}
