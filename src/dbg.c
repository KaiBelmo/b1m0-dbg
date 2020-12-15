#include "dbg.h"

#include "breakpoint.h"
#include "elf_parser.h"
#include "proc.h"

void insert_cmd(commandline **start, char *command) {
    commandline *tmp = malloc(sizeof(commandline));
    if (tmp == NULL) {
        return;
    }
    commandline *ptr = (*start);
    
    tmp->str = (char *)malloc((strlen(command) * sizeof(char)) + 1);
    strncpy(tmp->str, command, strlen(command));
    tmp->next = NULL;
    if ((*start) == NULL) {
        (*start) = tmp;
    } else {
        while (ptr->next != NULL) ptr = ptr->next;
        ptr->next = tmp;
    }
}

void print_cmd(commandline *cmd)
{
	commandline *current = cmd;
    int counter = 0;
	while (current) {
		printf(WHITE "\t\t%d:\x1B[0m %s\n", counter, current->str);
		current = current->next;
        counter++;
	}
}

int handle_cmd(char *cmd) {
    if ((strncmp(cmd, "single_step", 11) == 0 || strncmp(cmd, "s", 1) == 0))     // single step
        return 0;
    else if ((strncmp(cmd, "history", 11) == 0 || strncmp(cmd, "hs", 2) == 0))   // commands history
        return 1;
    else if (strncmp(cmd, "info", 4) == 0)                                       // parse elf file (info file, info symbols, info section, info pid)
        return 2;
    else if ((strncmp(cmd, "q", 1) == 0 || (strncmp(cmd, "quit", 4) == 0)))      // my fav command
        return 3;
    else if ((strncmp(cmd, "regs", 4) == 0 || (strncmp(cmd, "r", 1) == 0)))      // dump all registers
        return 4;
    else if ((strncmp(cmd, "continue", 11) == 0 || (strncmp(cmd, "c", 1) == 0))) // continue execution
        return 5;
    else if (strncmp(cmd, "trace_sys", 9) == 0)                                  // trace syscalls
        return 6;
    else if (strncmp(cmd, "next_syscall", 12) == 0)                              // step to next syscalls
        return 7;
    else if (strncmp(cmd, "break", 5) == 0)                                      // breakpoint
        return 8;
    else if (strncmp(cmd, "print_bp", 8) == 0)                                   // print all breakpoints
        return 9;
    else if ((strncmp(cmd, "print_memory", 12) == 0) || (strncmp(cmd, "mem", 3) == 0))  
        return 10;                                                              // print memory
    return -1;
}

char *set_program_name(char *argv, char *buffer) {
    int i = 0;
    buffer = (char *)malloc(sizeof(char) + 1);
    while (argv[i] != '\0') {
        buffer = (char *)realloc(buffer, sizeof(char));
        strcat(buffer, &argv[i]);
        i++;
    }
    return buffer;
}

char *command_input() {
    char *string_input = (char *)malloc(sizeof(char));
    if (string_input != NULL) {
        char c = EOF;
        unsigned int size = 0;
        while ((c = getchar()) != '\n' && c != EOF) {
            string_input[size++] = c;
            string_input = (char *)realloc(string_input, size + 1);
        }
        string_input[size] = '\0';
    }
    return string_input;
}

void unimplemented(void){
    printf("unimplemented!\n");
}