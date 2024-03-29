## b1m0-debugger
Linux (debugger, syscall tracer, elf parser) for x86_64, I code it from scratch for educational purpose.

#### <strong> Features </strong> 

  
<details>
  <summary><strong>Parsing Elf File</strong></summary>
  
  * Display the ELF file header.
  * Display the program headers.
  * Display the sections' header.
</details>


  
<details>
  <summary><strong>Tracing syscalls</strong></summary>
  
  * Trace syscalls (like strace).
  * Continue execution until syscall.
  * Tracing specific syscall <strong>(unimplemented)</strong>.
</details>
 
 
  
<details>
  <summary><strong>Check executable security mitigation</strong></summary>
  
  * RELRO.
  * NoExecute (NX).
  * Position Independent Executables (PIE).
  * Stack Canaries <strong>(unimplemented)</strong>.
</details>


 
<details>
  <summary><strong>Stepping</strong></summary>
  
  * Single step - step over function calls.
  * Step out of the present function.
  * Step to <strong>_start</strong>
  * Step in - Step into function calls <strong>(unimplemented)</strong>.
</details>


  
<details>
  <summary><strong>Get/Set Registers</strong></summary>
  
  * Dump all registers.
  * Modify specific register.
</details>


<details>
  <summary><strong>Breakpoints</strong></summary>
  
  * Set breakpoints.
  * list all breakpoint.
</details>
 
  
<details>
  <summary><strong>Process information</strong></summary>
  
  * Show the original command line of the process.
  * Show the memory address space ranges accessible in a process.
</details>
 
Check wiki page for all commands.
 
#### <strong> Dependencies </strong>
 * [GNU Readline Library](https://tiswww.case.edu/php/chet/readline/rltop.html)
 
***note*** *While I'm trying to code an elf parser, I discovered an anti-debug technique on gdb. [POC](https://twitter.com/belmo01/status/1433197860288442372) | [poc.c](https://gist.github.com/KaiBelmo/16cc06ae99b81e601f912edf906e5670)*
