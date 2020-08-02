/*
	Spaghetti code!
*/

#include "inc/parser.h"
#include "inc/dbg.h"

struct user_regs_struct regs;
h_cmd			*h_command = NULL;
break_p			*break_point = NULL;

int	main(int argc, char** argv){

	Elf64_Ehdr	header;
	Elf64_Shdr* shdr;

	char		 address[17];
	char		 *prog;
	int			 status = {0};
	unsigned long long int break_address;
	unsigned long long int instruction;
	int32_t		 fd;
	pid_t		 pid;
	shdr = 0;

	prog	= argv[1];
	//prog = "asdf.out";
	fd		= open(prog, O_RDONLY|O_SYNC);
	char cmd[15];

	if (argc < 2){
		f_usage(argv[0]);
		return -1;
	}
	if (f_check(prog)){
		return -2;
	}
	if (!(f_check_elf(fd, &header))){
			printf("Reading info from executable\n");
	}
	else {
			printf("\t Check your executable!\n");
			return -3;
	}

	pid	= fork();
	if (pid == -1){
			perror ("fork");
			return -4;
	}
	if (pid == 0) {
		child_process(prog);
	}
     else if (pid >= 1)  {
		usleep(200000);
		printf("Attaching to pid %d\n", pid); 
		waitchild(pid);
		while(1){
				printf("\x1B[31;1m[B1MO:0x%llx]>\x1B[0m", regs.rip);
				fgets(cmd, 14, stdin);
				insert_cmd(&h_command, cmd);
				strtok(cmd, "\n");
				fflush(stdin);
				switch(handle_cmd(cmd)){
						case 0:
							single_step(pid, &regs);
							break;
						case 1:
							print_cmd(h_command);
							break;
						case 2:
							//info header / info section / info symbols
							if(strcmp(cmd, "info file") == 0){
									info_header(header);
							}
							else if(strcmp(cmd, "info section") == 0){
								print_section(header, shdr, fd);
							}
							else if(strcmp(cmd, "info symbols") == 0){
								print_symbols(header, shdr, fd);
								// laateeeer
							}
							break;
						case 3:
						// kill the child :(
							kill(pid, SIGKILL);
							goto EXIT;
							break;
						case 4:
							info_regs(&regs, pid);
							break;
						case 5:
							cont_step(pid);
							//err = ptrace(PTRACE_CONT, pid, NULL, NULL);
							wait(&status);
							goto EXIT;
							break;
						case 6:
							trace_syscall(pid);
							break;
						case 7:
							step_syscall(pid, &regs);
							break;
						case 8:
							printf("address: ");
							fgets(address, 16, stdin);
							break_address = (unsigned long long int)strtol(address, NULL, 16);
							add_break_point(&break_point, break_address);
							instruction = set_break_p(pid, break_address);  
							ptrace(PTRACE_CONT, pid, 0, 0);

							wait(&status);
							if (WIFSTOPPED(status)) {
									ptrace(PTRACE_POKETEXT, pid, address, instruction);
							}
							ptrace(PTRACE_GETREGS, pid, NULL, &regs);
							regs.rip = break_address;
							set_ins(pid, break_address, instruction);
							ptrace(PTRACE_SETREGS, pid, NULL, &regs);
							// i will fix it laterrrr
							break;
						case 9:
							print_break_points(break_point);
							break;
						case 10:
							print_memory(pid);
							break;
				}
				//strcpy(cmd, "");
		}
	}
	EXIT:
	printf("Exit...");

	return 0;
}
