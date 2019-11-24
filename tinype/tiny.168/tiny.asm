; tiny.asm

BITS 32

;
; MZ header
;
; The only two fields that matter are e_magic and e_lfanew

mzhdr:
    dw "MZ"       ; e_magic
    dw 0          ; e_cblp UNUSED

;
; PE signature
;

pesig:
    dd "PE"       ; e_cp, e_crlc UNUSED       ; PE signature

;
; PE header
;

pehdr:
    dw 0x014C     ; e_cparhdr UNUSED          ; Machine (Intel 386)
    dw 1          ; e_minalloc UNUSED         ; NumberOfSections
    dd 0x4545BE5D ; e_maxalloc, e_ss UNUSED   ; TimeDateStamp UNUSED
    dd 0          ; e_sp, e_csum UNUSED       ; PointerToSymbolTable UNUSED
    dd 0          ; e_ip, e_cs UNUSED         ; NumberOfSymbols UNUSED
    dw opthdrsize ; e_lsarlc UNUSED           ; SizeOfOptionalHeader
    dw 0x103      ; e_ovno UNUSED             ; Characteristics

;
; PE optional header
;
; The debug directory size at offset 0x94 from here must be 0

filealign equ 4
sectalign equ 4   ; must be 4 because of e_lfanew

%define round(n, r) (((n+(r-1))/r)*r)

opthdr:
    dw 0x10B      ; e_res UNUSED              ; Magic (PE32)
    db 8                                      ; MajorLinkerVersion UNUSED
    db 0                                      ; MinorLinkerVersion UNUSED
    dd round(codesize, filealign)             ; SizeOfCode UNUSED
    dd 0          ; e_oemid, e_oeminfo UNUSED ; SizeOfInitializedData UNUSED
    dd 0          ; e_res2 UNUSED             ; SizeOfUninitializedData UNUSED
    dd start                                  ; AddressOfEntryPoint
    dd code                                   ; BaseOfCode UNUSED
    dd round(filesize, sectalign)             ; BaseOfData UNUSED
    dd 0x400000                               ; ImageBase
    dd sectalign  ; e_lfanew                  ; SectionAlignment
    dd filealign                              ; FileAlignment
    dw 4                                      ; MajorOperatingSystemVersion UNUSED
    dw 0                                      ; MinorOperatingSystemVersion UNUSED
    dw 0                                      ; MajorImageVersion UNUSED
    dw 0                                      ; MinorImageVersion UNUSED
    dw 4                                      ; MajorSubsystemVersion
    dw 0                                      ; MinorSubsystemVersion UNUSED
    dd 0                                      ; Win32VersionValue UNUSED
    dd round(filesize, sectalign)             ; SizeOfImage
    dd round(hdrsize, filealign)              ; SizeOfHeaders
    dd 0                                      ; CheckSum UNUSED
    dw 2                                      ; Subsystem (Win32 GUI)
    dw 0x400                                  ; DllCharacteristics UNUSED
    dd 0x100000                               ; SizeOfStackReserve
    dd 0x1000                                 ; SizeOfStackCommit
    dd 0x100000                               ; SizeOfHeapReserve
    dd 0x1000                                 ; SizeOfHeapCommit UNUSED
    dd 0                                      ; LoaderFlags UNUSED
    dd 0                                      ; NumberOfRvaAndSizes UNUSED

opthdrsize equ $ - opthdr

;
; PE code section
;

    db ".text", 0, 0, 0                       ; Name
    dd codesize                               ; VirtualSize
    dd round(hdrsize, sectalign)              ; VirtualAddress
    dd round(codesize, filealign)             ; SizeOfRawData
    dd code                                   ; PointerToRawData
    dd 0                                      ; PointerToRelocations UNUSED
    dd 0                                      ; PointerToLinenumbers UNUSED
    dw 0                                      ; NumberOfRelocations UNUSED
    dw 0                                      ; NumberOfLinenumbers UNUSED
    dd 0x60000020                             ; Characteristics UNUSED

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
