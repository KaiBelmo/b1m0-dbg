#include "../inc/dbg.h"

static char *syscall_names[314] = {"read","write","open","close","stat","fstat","lstat","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","rt_sigreturn","ioctl","pread64","pwrite64","readv","writev","access","pipe","select","sched_yield","mremap","msync","mincore","madvise","shmget","shmat","shmctl","dup","dup2","pause","nanosleep","getitimer","alarm","setitimer","getpid","sendfile","socket","connect","accept","sendto","recvfrom","sendmsg","recvmsg","shutdown","bind","listen","getsockname","getpeername","socketpair","setsockopt","getsockopt","clone","fork","vfork","execve","exit","wait4","kill","uname","semget","semop","semctl","shmdt","msgget","msgsnd","msgrcv","msgctl","fcntl","flock","fsync","fdatasync","truncate","ftruncate","getdents","getcwd","chdir","fchdir","rename","mkdir","rmdir","creat","link","unlink","symlink","readlink","chmod","fchmod","chown","fchown","lchown","umask","gettimeofday","getrlimit","getrusage","sysinfo","times","ptrace","getuid","syslog","getgid","setuid","setgid","geteuid","getegid","setpgid","getppid","getpgrp","setsid","setreuid","setregid","getgroups","setgroups","setresuid","getresuid","setresgid","getresgid","getpgid","setfsuid","setfsgid","getsid","capget","capset","rt_sigpending","rt_sigtimedwait","rt_sigqueueinfo","rt_sigsuspend","sigaltstack","utime","mknod","uselib","personality","ustat","statfs","fstatfs","sysfs","getpriority","setpriority","sched_setparam","sched_getparam","sched_setscheduler","sched_getscheduler","sched_get_priority_max","sched_get_priority_min","sched_rr_get_interval","mlock","munlock","mlockall","munlockall","vhangup","modify_ldt","pivot_root","_sysctl","prctl","arch_prctl","adjtimex","setrlimit","chroot","sync","acct","settimeofday","mount","umount2","swapon","swapoff","reboot","sethostname","setdomainname","iopl","ioperm","create_module","init_module","delete_module","get_kernel_syms","query_module","quotactl","nfsservctl","getpmsg","putpmsg","afs_syscall","tuxcall","security","gettid","readahead","setxattr","lsetxattr","fsetxattr","getxattr","lgetxattr","fgetxattr","listxattr","llistxattr","flistxattr","removexattr","lremovexattr","fremovexattr","tkill","time","futex","sched_setaffinity","sched_getaffinity","set_thread_area","io_setup","io_destroy","io_getevents","io_submit","io_cancel","get_thread_area","lookup_dcookie","epoll_create","epoll_ctl_old","epoll_wait_old","remap_file_pages","getdents64","set_tid_address","restart_syscall","semtimedop","fadvise64","timer_create","timer_settime","timer_gettime","timer_getoverrun","timer_delete","clock_settime","clock_gettime","clock_getres","clock_nanosleep","exit_group","epoll_wait","epoll_ctl","tgkill","utimes","vserver","mbind","set_mempolicy","get_mempolicy","mq_open","mq_unlink","mq_timedsend","mq_timedreceive","mq_notify","mq_getsetattr","kexec_load","waitid","add_key","request_key","keyctl","ioprio_set","ioprio_get","inotify_init","inotify_add_watch","inotify_rm_watch","migrate_pages","openat","mkdirat","mknodat","fchownat","futimesat","newfstatat","unlinkat","renameat","linkat","symlinkat","readlinkat","fchmodat","faccessat","pselect6","ppoll","unshare","set_robust_list","get_robust_list","splice","tee","sync_file_range","vmsplice","move_pages","utimensat","epoll_pwait","signalfd","timerfd_create","eventfd","fallocate","timerfd_settime","timerfd_gettime","accept4","signalfd4","eventfd2","epoll_create1","dup3","pipe2","inotify_init1","preadv","pwritev","rt_tgsigqueueinfo","perf_event_open","recvmmsg","fanotify_init","fanotify_mark","prlimit64","name_to_handle_at","open_by_handle_at","clock_adjtime","syncfs","sendmmsg","setns","getcpu","process_vm_readv","process_vm_writev","kcmp","finit_module"};


void child_process(char* prog){
    // Allow tracing of this process
	if (ptrace(PTRACE_TRACEME, NULL, NULL, NULL) < 0) {
		perror("ptrace");
        return;
    }
	// Replace this process's image with the given program 
	execl(prog, prog, NULL);
}

void single_step(pid_t pid, struct user_regs_struct *regs) {
	int st;
	ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
	wait(&st); 
	ptrace(PTRACE_GETREGS, pid, 0, regs);
}

void insert_cmd(h_cmd **start, char* str){
    h_cmd *new = malloc(sizeof(h_cmd));
    h_cmd *ptr = (*start);
    new->str = malloc(12 * sizeof(char)); 
    strcpy(new->str, str);
    (new)->next = NULL;
    if ((*start) == NULL) {
        (*start) = new;
    }
    else {
        while (ptr->next != NULL)
            ptr = ptr->next;
        ptr->next = new;
    }
}

void print_cmd(h_cmd *cmd){
	int counter = 1;
	if(cmd == NULL){
		return;
	}
	else{
		printf("\x1B[37;1mlist of commands:\n");
		while (cmd != NULL){
		    printf("\t\t\x1B[37;1m%d:\x1B[0m %s", counter, cmd->str);
		    cmd = cmd->next;
		    counter++;
		}
	}
}

int handle_cmd(char *cmd){
	if(strncmp(cmd, "si", 2) == 0)			// single step
			return 0;
	else if(strncmp(cmd, "hs", 2) == 0)		// commands history
			return 1;
	else if(strncmp(cmd, "info", 4) == 0)		// parse elf file (info file, info symbols, info section)
			return 2;
	else if((strncmp(cmd, "q", 2) == 0) )		// my fav command
			return 3;
	else if(strncmp(cmd,"regs", 4) == 0)		// dump all registers
			return 4;
	else if(strncmp(cmd, "c", 1) == 0)		// continue execution
			return 5;
	else if(strncmp(cmd, "st", 2) == 0)		// trace syscalls 
			return 6;
	else if(strncmp(cmd, "sy", 2) == 0)		// step to next syscalls
			return 7;
	else if(strncmp(cmd, "b", 1) == 0)		// breakpoint 
			return 8;
	else if(strncmp(cmd, "print_bp", 8) == 0)	// print all breakpoints
			return 9;
	else if(strncmp(cmd, "mem", 3) == 0)		// print memory
			return 10;
	return -1;
}

void info_regs(struct user_regs_struct *regs, pid_t pid){
	printf("\n\x1B[37;1mPrint Registers:\x1B[0m\n\n");
	printf("\x1B[37;1mRAX: \x1B[0m0x%llx \x1B[37;1mRBX: \x1B[0m0x%llx \x1B[37;1mRCX: \x1B[0m0x%llx \x1B[37;1mRDX: \x1B[0m0x%llx\n", regs->rax, regs->rbx, regs->rcx, regs->rdx);
    	printf("\x1B[37;1mR15: \x1B[0m0x%llx \x1B[37;1mR14: \x1B[0m0x%llx \x1B[37;1mR13: \x1B[0m0x%llx \x1B[37;1mR12: \x1B[0m0x%llx\n", regs->r15, regs->r14, regs->r13, regs->r12);
    	printf("\x1B[37;1mR11: \x1B[0m0x%llx \x1B[37;1mR10: \x1B[0m0x%llx \x1B[37;1mR9:  \x1B[0m0x%llx \x1B[37;1mR8:  \x1B[0m0x%llx\n", regs->r11, regs->r10, regs->r9, regs->r8);
    	printf("\x1B[37;1mRSP: \x1B[0m0x%llx \x1B[37;1mRBP: \x1B[0m0x%llx \x1B[37;1mRSI: \x1B[0m0x%llx \x1B[37;1mRDI: \x1B[0m0x%llx\n", regs->rsp, regs->rbp, regs->rsi, regs->rdi);
   	printf("\x1B[37;1mRIP: \x1B[0m0x%llx \x1B[37;1mCS:  \x1B[0m0x%llx \x1B[37;1mEFLAGS:\x1B[0m0x%llx\n",       regs->rip, regs->cs, regs->eflags);
   	printf("\x1B[37;1mSS:  \x1B[0m0x%llx \x1B[37;1mDS:  \x1B[0m0x%llx \x1B[37;1mES:  \x1B[0m0x%llx \x1B[37;1mFS:  \x1B[0m0x%llx \x1B[37;1mGS:  \x1B[0m0x%llx\n",regs->ss, regs->ds, regs->es, regs->fs, regs->gs);

	printf("\n\x1B[37;1mPrint Stack:\x1B[0m\n\n");
	long long value = 0;
	value = ptrace(PTRACE_PEEKDATA, pid, regs->rsp, NULL);
	printf("\x1B[37;1m0x%llx | \x1B[0m0x%llx\n", regs->rsp, value);
	for (int i = 1; i < 10; i++){
        value = ptrace(PTRACE_PEEKDATA, pid, regs->rsp + i * 8, NULL);
		printf("\x1B[37;1m0x%llx | \x1B[0m0x%llx\n", regs->rsp + i * 8, value);
	}
	
}

void cont_step(pid_t pid) {
	int status;
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	wait(&status); 
	if (WIFEXITED(status)) {
		printf("\n\x1B[37;1mreturn value %d\n", WEXITSTATUS(status));
		return;
	}
}

void trace_syscall(pid_t pid) {
	int status;
	printf("\n\x1B[37;1msyscall\t\t Address\t Flag\x1B[0m\n");
	while (!WIFEXITED(status)) {
		struct user_regs_struct regs;
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
		waitpid(pid, &status, 0);
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
		wait(&status);
		int syscall;
		ptrace(PTRACE_GETREGS, pid, 0, &regs);
		syscall = regs.orig_rax;
		printf("%s\t\t", syscall_names[syscall-1]);
		printf(" 0x%08llx\t", regs.rbx);
		printf(" 0x%08llx\t\n", regs.rcx);
	}
}

void step_syscall(pid_t pid, struct user_regs_struct *regs){
	int status; 
	ptrace(PTRACE_SYSCALL, pid, 0, 0);
	wait(&status);
	ptrace(PTRACE_GETREGS, pid, 0, regs);

}

void add_break_point(break_p **start, long long int address){
    break_p *new_node, *ptr = *start;
    new_node = (break_p*)malloc(sizeof(break_p));

    new_node->addr = address;
    new_node->next = NULL;

    if ((*start) == NULL) {
        (*start) = new_node;
    } else {
        while (ptr->next != NULL)
            ptr = ptr->next;
        ptr->next = new_node;
    }
}

void print_break_points(break_p *head){
	int counter = 1;
	while(head != NULL){
		printf("%d- at 0x%llu\n", counter, head->addr);
		head = head->next;
		counter++;
	}
}

unsigned int handle_addr(char *str){
    char addr[10];
    strncpy(addr, str + 4, 8);
    unsigned int address = (unsigned)atoi(addr);
    return address;
}

void print_memory(pid_t pid){
	char path[25];
	FILE* fp;
	char c;
	sprintf(path, "/proc/%d/maps", pid);
	//printf("%s", path);
	fp = fopen(path, "r");
	if (fp) {
		while ((c = getc(fp)) != EOF)
			putchar(c);
		fclose(fp);
	}
}

int waitchild(pid_t pid) {
    int status;
    waitpid(pid, &status, 0);
    if(WIFSTOPPED(status)) {
        return 0;
    }
    else if (WIFEXITED(status)) {
        return 1;
    }
    else 
        return 1;
}

unsigned long readfrom(pid_t pid, unsigned long address) {
  return ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
}

void set_ins(pid_t pid, unsigned long address, unsigned long instruction) {
  ptrace(PTRACE_POKETEXT, pid, address, instruction);
}

unsigned long long set_break_p(pid_t pid, unsigned long long address) {
    unsigned long long org = readfrom(pid, address);
	
    unsigned long long bp = org;
	// i'm too lazy todo some bitwise operations
    ((char*)&bp)[0] = 0xcc;
    set_ins(pid, address, bp);
    printf("Set breakpoint at %llx\n", address);
	return org;
}
