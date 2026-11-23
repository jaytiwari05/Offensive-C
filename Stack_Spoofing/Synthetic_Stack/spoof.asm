default rel
section .text
global Spoof

; SPOOF_CTX field offsets (must match struct.h)
%define CTX_RUTS_RET      0
%define CTX_RUTS_FRAME    8
%define CTX_BTIT_RET      16
%define CTX_BTIT_FRAME    24 
%define CTX_GADGET_ADDR   32
%define CTX_GADGET_FRAME  40
%define CTX_TARGET_FUNC   48

%define CTX_ARG_COUNT     56
%define CTX_RESTORE_ADDR  64
%define CTX_ARGS          72

Spoof:
    ; ---------- Phase 1 - Save State ----------

    ; CALL pushed a return address on the stack, Pop it immediately , showing up in the fake call chain

    pop r15         ; save our return address (back to C)

    push r12        ; save non-volatile registers
    push r13        ; (x64 ABI says we must preserve these)
    push rbx
    push rbp

    mov r13, rcx    ; R13 = Pointer to SPOOF_CTX (RCX = 1st arg)
    mov r12, rsp    ; R12 = RSP checkpoint (one-instruction restore later)

    ; ---------- Phase 2 - Aligment pre-check ----------

    ; Target expects RSP = 16n+8 at entry (as if CALL pushed 8)
    ; After 4 pushes, RSP is 16-aligned
    ; We'll subtract (3 frame sizes + 4 pushes = 32 bytes for ret addrs+terminator)

    mov rax, [r13 + CTX_RUTS_FRAME]
    add rax, [r13 + CTX_BTIT_FRAME]
    add rax, [r13 + CTX_GADGET_FRAME]
    add rax, 32     ; 4 pushes: terminator + 3 return addrs
    test eax, 8     ; bit 3 set? (sum = 8 mod 16)
    jnz .build_frames ; yes -> alignment correct
    sub rsp, 8      ; no -> pad 8 bytes to fix it

.build_frames:
    ; ---------- Phase 3: Build synthectic frames (bottom -> top) ----------
    ; Unwinder walks top->bottom and sees:
    ; Gadget -> BTIT+0x14 -> RUTS+0x21 -> NULL

    ; Terminator (NULL = end of call chain)
    push 0

    ; Frame 3 (bottom) : RtlUserThreadStart
    ; This line is for adding the padding between 0x00 <-> RUTS
    mov r10, [r13 + CTX_RUTS_FRAME]
    sub rsp, r10 
    mov r10, [r13 + CTX_RUTS_RET]
    push r10
    
    ; Frame 2 (middle): BaseThreadInitThunk
    ; This line is for adding the padding between RUTS <-> BTIT
    mov r10, [r13 + CTX_BTIT_FRAME]
    sub rsp, r10
    mov r10, [r13 + CTX_BTIT_RET]
    push r10

    ; Frame 1 (top): Gadget
    ; This line is for adding the padding between BTIT <-> Gadget
    mov r10, [r13 + CTX_GADGET_FRAME]
    sub rsp, r10
    mov r10, [r13 + CTX_GADGET_ADDR]
    push r10
    ; RSP now points to gadget addr
    ; Target's RET will pop this as its "return address"

    ; ---------- Phase 4 Set up arguments ----------

    ; x64 args 1-4 in RCX, RDX, R8, R9
    ; args 5+ on stack at [RSP+32+k*8]

    lea r10, [r13 + CTX_ARGS]    ; R10 = &args[0]
    mov rcx, [r10]               ; arg 1
    mov rdx, [r10 + 8]           ; arg 2
    mov r8,  [r10 + 16]          ; arg 3
    mov r9,  [r10 + 24]          ; arg 4

    ; Extra args (5+): loop from (argCount-4) down to 1
    mov rbp, [r13 + CTX_ARG_COUNT]
    sub rbp, 4

.place_args:
    cmp rbp, 0
    jle .setup_rbx
    mov r11, [r10 + rbp*8 +24]  ; load arg from array
    mov [rsp + 32 + rbp*8], r11 ; place on stack past shadow space
    dec rbp
    jmp .place_args

    ; ---------- Phase 5 Set up RBX trampoline ----------
    ; Gadget = jmp [rbx] -> reads QWORD at [RBX] -> jump there
    ; We store restore label addr in struct, point RBX at that field

.setup_rbx:
    lea r10, [.restore]                 ; R10 = address of restore code
    mov [r13 + CTX_RESTORE_ADDR], r10   ; store in struct
    lea rbx, [r13 + CTX_RESTORE_ADDR]   ; RBX -> struct field

    ; ---------- Phase 6  Execute target ----------
    ; JMP not CALL we don't want another return addr pushed
    ; Flow: target RET -> gadget (jmp [rbx]) -> restore
    mov r10, [r13 + CTX_TARGET_FUNC]
    jmp r10

    ; ---------- Phase 7 Restore ----------
    ; We land here via: target RET -> gadget jmp [rbx] -> here
    ; RAX = target's return value Don't touch it

.restore:
    mov rsp, r12        ; one instruction undoes ALL frame construction

    pop rbp             ; restore non-volatiles (reverse push order)
    pop rbx
    pop r13
    pop r12

    jmp r15             ; return to C caller (RAX passes through)

