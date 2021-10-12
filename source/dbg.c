#include "dbg.h"
#include "proc.h"
#include "regs.h"
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/user.h>
#include "breakpoint.h"
#include <sys/types.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <readline/readline.h>

int usage(char *argv[]) { return fprintf(stderr, WHITE "\tUsage: %s <executable>\n", argv[0]); }

int string_compare(char *str1, char *str2, size_t size)
{
    int result = 0;
    if (strlen(str2) == 0){
        return -1;
    }
    while (size--)
    {
        if (isspace(*str1) != 0){
            str1++;
        }
        if (isspace(*str2) != 0){
            str2++;
        }
        if (isprint(*str1) != 0 && isprint(*str2) != 0)
        {
            result += abs(tolower(*str1) - tolower(*str2));
            str1++;
            str2++;
        }
        if (*str1 == '\0' && *str2 == '\0')
            return (result == 0) ? 0 : -1;
        else if (*str2 == '\0')
            return 1;
    }
    return (result == 0) ? 0 : -1;
}

int check_file_permissions(char *pathname)
{
  if (access(pathname, F_OK) == -1)
  {
    fprintf(stderr, "ERROR: file does not exist.\n");
    return -1;
  }
  if (access(pathname, X_OK) == -1)
  {
    fprintf(stderr, "ERROR: check file permission.\n");
    return -1;
  }
  return 0;
}

char *get_userinput(void)
{
    char *user_input = readline(" ");
    if (user_input == NULL){
        perror("readline");
    }
    return user_input;
}

int is_printable(char *str)
{
    int result = 0;
    while (*str)
    {
        result += isprint(*str);
        str++;
    }
    return (result != 0) ? 0 : 1;
}

int single_step(child_proc *proc, int *status, breakpoint *breakpoint_list)
{
    if (ptrace(PTRACE_SINGLESTEP, proc->pid, 0, 0) == -1)
    {
        perror("ptrace_singlestep");
        return -1;
    }
    *status = wait_tracee(proc, breakpoint_list);
    return 0;
}

int continue_execution(child_proc *proc, int *status, breakpoint *breakpoint_list){
  if (ptrace(PTRACE_CONT, proc->pid, 0, 0) == -1)
  {
    perror("ptrace_continue");
    return -1;
  }
  *status = wait_tracee(proc, breakpoint_list);
  return 0;
}

size_t set_address(char *command){
  while(command){
    if(*command == '*'){
      return strtoul(++command, NULL, 16);
    }
    command++;
  }
  return -1;
} 

void unimplemented(void)
{
    printf("unimplemented!");
}

int step_out(child_proc *proc, int *status, breakpoint *breakpoint_list, struct user_regs_struct *regs)
{
  unimplemented();
  (void)proc;
  (void)status;
  (void)breakpoint_list;
  (void)regs;
  // size_t data = 0, rip = 0;
  // get regs, get op code and check
  // while (*status == RUNNING)
  // {
  //   if (ptrace(PTRACE_SINGLESTEP, proc->pid, 0, 0) == -1)
  //   {
  //     perror("ptrace_singlestep");
  //     return -1;
  //   }
  //   *status = wait_tracee(proc, breakpoint_list);
  // }
  return 0;
}

// this is not my code.
ssize_t str_to_hex(const char * str) {
    ssize_t result = 0;
    const size_t maxChars = sizeof( result );
    for ( size_t i = 0; i < maxChars && str[ i ]; ++i ) {
        result <<= 8;
        result |= str[ i ];
    }
    return result;
}