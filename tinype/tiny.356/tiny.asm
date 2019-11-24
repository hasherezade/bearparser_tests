; tiny.asm

BITS 32

;
; MZ header
;
; The only two fields that matter are e_magic and e_lfanew

mzhdr:
    dw "MZ"                       ; e_magic
    dw 0                          ; e_cblp UNUSED
    dw 0                          ; e_cp UNUSED
    dw 0                          ; e_crlc UNUSED
    dw 0                          ; e_cparhdr UNUSED
    dw 0                          ; e_minalloc UNUSED
    dw 0                          ; e_maxalloc UNUSED
    dw 0                          ; e_ss UNUSED
    dw 0                          ; e_sp UNUSED
    dw 0                          ; e_csum UNUSED
    dw 0                          ; e_ip UNUSED
    dw 0                          ; e_cs UNUSED
    dw 0                          ; e_lsarlc UNUSED
    dw 0                          ; e_ovno UNUSED
    times 4 dw 0                  ; e_res UNUSED
    dw 0                          ; e_oemid UNUSED
    dw 0                          ; e_oeminfo UNUSED
    times 10 dw 0                 ; e_res2 UNUSED
    dd pesig                      ; e_lfanew

;
; PE signature
;

pesig:
    dd "PE"

;
; PE header
;

pehdr:
    dw 0x014C                     ; Machine (Intel 386)
    dw 1                          ; NumberOfSections
    dd 0x4545BE5D                 ; TimeDateStamp UNUSED
    dd 0                          ; PointerToSymbolTable UNUSED
    dd 0                          ; NumberOfSymbols UNUSED
    dw opthdrsize                 ; SizeOfOptionalHeader
    dw 0x103                      ; Characteristics (no relocations, executable, 32 bit)

;
; PE optional header
;

filealign equ 1
sectalign equ 1

%define round(n, r) (((n+(r-1))/r)*r)

opthdr:
    dw 0x10B                      ; Magic (PE32)
    db 8                          ; MajorLinkerVersion UNUSED
    db 0                          ; MinorLinkerVersion UNUSED
    dd round(codesize, filealign) ; SizeOfCode UNUSED
    dd 0                          ; SizeOfInitializedData UNUSED
    dd 0                          ; SizeOfUninitializedData UNUSED
    dd start                      ; AddressOfEntryPoint
    dd code                       ; BaseOfCode UNUSED
    dd round(filesize, sectalign) ; BaseOfData UNUSED
    dd 0x400000                   ; ImageBase
    dd sectalign                  ; SectionAlignment
    dd filealign                  ; FileAlignment
    dw 4                          ; MajorOperatingSystemVersion UNUSED
    dw 0                          ; MinorOperatingSystemVersion UNUSED
    dw 0                          ; MajorImageVersion UNUSED
    dw 0                          ; MinorImageVersion UNUSED
    dw 4                          ; MajorSubsystemVersion
    dw 0                          ; MinorSubsystemVersion UNUSED
    dd 0                          ; Win32VersionValue UNUSED
    dd round(filesize, sectalign) ; SizeOfImage
    dd round(hdrsize, filealign)  ; SizeOfHeaders
    dd 0                          ; CheckSum UNUSED
    dw 2                          ; Subsystem (Win32 GUI)
    dw 0x400                      ; DllCharacteristics UNUSED
    dd 0x100000                   ; SizeOfStackReserve UNUSED
    dd 0x1000                     ; SizeOfStackCommit
    dd 0x100000                   ; SizeOfHeapReserve
    dd 0x1000                     ; SizeOfHeapCommit UNUSED
    dd 0                          ; LoaderFlags UNUSED
    dd 16                         ; NumberOfRvaAndSizes UNUSED

;
; Data directories
;

    times 16 dd 0, 0

opthdrsize equ $ - opthdr

;
; PE code section
;

    db ".text", 0, 0, 0           ; Name
    dd codesize                   ; VirtualSize
    dd round(hdrsize, sectalign)  ; VirtualAddress
    dd round(codesize, filealign) ; SizeOfRawData
    dd code                       ; PointerToRawData
    dd 0                          ; PointerToRelocations UNUSED
    dd 0                          ; PointerToLinenumbers UNUSED
    dw 0                          ; NumberOfRelocations UNUSED
    dw 0                          ; NumberOfLinenumbers UNUSED
    dd 0x60000020                 ; Characteristics (code, execute, read) UNUSED

hdrsize equ $ - $$

;
; PE code section data
;

align filealign, db 0

code:

; Entry point

start:
    push byte 42
    pop eax
    ret

codesize equ $ - code

filesize equ $ - $$
