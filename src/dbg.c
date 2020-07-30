#include "dbg.h"

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
	else if(strncmp(cmd, "mem", 2) == 0)		// print memory
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
    printf("Set breakpoint at %lx\n", address, readfrom(pid, address));
	return org;
}
