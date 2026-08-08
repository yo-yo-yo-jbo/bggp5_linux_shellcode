[BITS 64]

; Constants
EXECVE_SYSCALL_NUM EQU 0x3B

        ; Make a dummy variable for bash
        db 'j='                         ; Interpreted as PUSH 0x3d

        ; Jump over argv
        call after_argv

        ; It just so happens the execve syscall number is ';' which is great for shell scripting
        db EXECVE_SYSCALL_NUM EQU

        ; argv and also commandline for bash
        db `/bin/curl -L 7f.uk\n`

        ; Exiting bash
        db `exit\n`

after_argv:

        ; Get the address that points to the execve syscall number
        pop rdi
        mov rsi, rdi

        ; Zero-out RAX and set envp by means of CDQ instruction onto RDX
        ; Note it's enough to zero EAX, saving a REX prefix
        xor eax, eax
        cdq

        ; Push the last NULL argument - argv[3]
        push rdx

        ; Replace \n and two spaces with \0 and prepare argv in stack in reverse order
        ; We work with RDI due to stosb instructions which will also increase after each store instruction
        cld
        add rdi, 19
        stosb
        sub rdi, 7
        stosb
        push rdi                ; argv[2]
        sub rdi, 4
        stosb
        push rdi                ; argv[1]

        ; Get the execve syscall number onto AL
        lodsb

        ; Push argv[0] - RSI increased after load instruction
        push rsi

        ; Make RDI point to main executable and RSI point to argv
        mov rdi, rsi
        mov rsi, rsp

        ; Call execve
        syscall
