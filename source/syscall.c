#include "proc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "syscall.h"
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include "breakpoint.h"
#include <linux/ptrace.h>

int trace_syscalls(child_proc *proc, int *status)
{
    const char *syscall_table[314] = {"read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module"};
    int wstatus = 0, err = 0;
    struct ptrace_syscall_info sysinfo = {0};

    while (1)
    {
        err = ptrace(PTRACE_SYSCALL, proc->pid, 0, 0);
        if (err == -1){
            perror("ptrace_syscall");
            return -1;
        }

        err = waitpid(proc->pid, &wstatus, 0);
        if (err == -1){
            perror("wait");
            return -1;
        }

        if (WIFEXITED(wstatus) == true)
        {
            printf("(Process %d exited with code %d)\n", proc->pid,
                   WEXITSTATUS(wstatus));
            *status = NOT_RUNNING;
            return 0;
        }
        else if (WIFSTOPPED(wstatus) == true && WSTOPSIG(wstatus) == (SIGTRAP | 0x80))
        {
            err = ptrace(PTRACE_GETREGS, proc->pid, 0, &(proc->regs));
            if (err == -1)
            {
                perror("ptrace_getregs");
                return -1;
            }
            err = ptrace(PTRACE_GET_SYSCALL_INFO, proc->pid, sizeof(struct ptrace_syscall_info), &sysinfo);
            if (err == -1)
            {
                perror("ptrace_getsyscall_info");
                return -1;
            }            
            switch (sysinfo.op)
            {
            case PTRACE_SYSCALL_INFO_ENTRY:
                printf("\x1B[37;1m%s\x1B[0m(", syscall_table[sysinfo.entry.nr]);
                size_t sizeofarray =
                    sizeof(sysinfo.entry.args) / sizeof(sysinfo.entry.args[0]);
                for (size_t i = 0; i < sizeofarray; i++)
                {
                    // access address to print arguments, maybe later xD
                    /*           
                    if (i == 1)
                    {
                      long word = ptrace(PTRACE_PEEKDATA, proc->pid, sysinfo.entry.args[i], NULL); 
                      char *tmp = (char*)&(word);
                      printf("%s ", tmp);
                    } */

                    printf("%lld", sysinfo.entry.args[i]);
                    if (i == (sizeofarray - 1))
                    {
                        break;
                    }
                    printf(", ");
                }
                printf(") ");
                break;
            case PTRACE_SYSCALL_INFO_EXIT:
                printf("= %lld\n", sysinfo.exit.rval);
                break;
            }
        }
    }
    return 0;
}

int step_syscall(child_proc *proc, int *status, breakpoint *breakpoint_list)
{
    if (ptrace(PTRACE_SYSCALL, proc->pid, 0, 0) == -1)
    {
        perror("ptrace_syscall");
        return -1;
    }
    *status = wait_tracee(proc, breakpoint_list);
    return 0;
}