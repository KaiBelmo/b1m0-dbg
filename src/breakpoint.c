#include "breakpoint.h"
#include "dbg.h"
#include "elf_parser.h"
#include "proc.h"


long unsigned set_address(char *buffer) {
    while(buffer++){
        if(*buffer == '*')
            return strtol(++buffer, NULL, 16);
        if(*buffer == '\0')
            return 1;
    }
}

void insert_in_breakpoint_list(struct breakpoint **breakpoint_list, long int address){
  struct breakpoint *new_node, *ptr;
  new_node = (struct breakpoint *)malloc(sizeof(struct breakpoint) + 1);
  new_node->break_address = address;
  
  if ((*breakpoint_list) == NULL) { 
    new_node->next = NULL;
    (*breakpoint_list) = new_node;
  } else {
    ptr = (*breakpoint_list);
    while (ptr->next != NULL){
        ptr = ptr->next;
    }
    ptr->next = new_node;
    new_node->next = NULL;
  }
}

void set_breakpoint_at_address(pid_t pid, size_t break_address, breakpoint** breakpoint_list){
    insert_in_breakpoint_list(breakpoint_list, break_address);
    enable_breakpoint(pid, breakpoint_list);
}

void enable_breakpoint(pid_t pid, breakpoint **breakpoint_list){
    int return_;
    uint64_t int3 = 0xCC;
    (*breakpoint_list)->old_opcode = ptrace(PTRACE_PEEKDATA, pid, (*breakpoint_list)->break_address, NULL);
    (*breakpoint_list)->new_opcode = (*breakpoint_list)->old_opcode;

    ((char*)&(*breakpoint_list)->new_opcode)[0] = int3;
    if (return_ = ptrace(PTRACE_POKEDATA, pid, (*breakpoint_list)->break_address, (*breakpoint_list)->new_opcode) != 0){
        perror("ptrace");
    }
    (*breakpoint_list)->status = ENABLED;
}

void disable_breakpoint(pid_t pid, breakpoint **breakpoint_list){
    if (ptrace(PTRACE_POKEDATA, pid, (*breakpoint_list)->break_address, (*breakpoint_list)->old_opcode) != 0){
        perror("ptrace");
    }
    (*breakpoint_list)->status = DISABLED;
}

void print_breakpoint_list(breakpoint *breakpoint_list) {
	while ( breakpoint_list != NULL) {
			printf(
					"break_address: 0x%lx - status: %s\n",
					breakpoint_list->break_address,
					breakpoint_list->status ? "enabled" : "disabled");
          breakpoint_list = breakpoint_list->next;
	}
}
/*
    int index;
    int status;
    size_t old_opcode;
    size_t new_opcode;
    size_t break_address;
*/