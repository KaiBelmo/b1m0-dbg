section     .data
        teststr:
        db        "test test", 10

section   .text
        global    _start
_start:
        mov       rax, 1
        mov       rdi, 1
        mov       rsi, teststr
        mov       rdx, 13
        syscall
        int3
