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
    dd "PE"       ; e_cp UNUSED          ; PE signature
                  ; e_crlc UNUSED

;
; PE header
;

pehdr:
    dw 0x014C     ; e_cparhdr UNUSED     ; Machine (Intel 386)
    dw 1          ; e_minalloc UNUSED    ; NumberOfSections

;   dd 0xC3582A6A ; e_maxalloc UNUSED    ; TimeDateStamp UNUSED
;                 ; e_ss UNUSED

; Entry point

start:
    push byte 42
    pop eax
    ret

    dd 0          ; e_sp UNUSED          ; PointerToSymbolTable UNUSED
                  ; e_csum UNUSED
    dd 0          ; e_ip UNUSED          ; NumberOfSymbols UNUSED
                  ; e_cs UNUSED
    dw sections-opthdr ; e_lsarlc UNUSED ; SizeOfOptionalHeader
    dw 0x103      ; e_ovno UNUSED        ; Characteristics

;
; PE optional header
;
; The debug directory size at offset 0x94 from here must be 0

filealign equ 4
sectalign equ 4   ; must be 4 because of e_lfanew

%define round(n, r) (((n+(r-1))/r)*r)

opthdr:
    dw 0x10B      ; e_res UNUSED         ; Magic (PE32)
    db 8                                 ; MajorLinkerVersion UNUSED
    db 0                                 ; MinorLinkerVersion UNUSED

;
; PE code section and IAT
;

sections:
iat:
    dd 0x80000001                        ; SizeOfCode UNUSED                  ; Name UNUSED                 ; Import function 1 by ordinal
    dd 0          ; e_oemid UNUSED       ; SizeOfInitializedData UNUSED                                     ; end of IAT
                  ; e_oeminfo UNUSED
    dd codesize   ; e_res2 UNUSED        ; SizeOfUninitializedData UNUSED     ; VirtualSize
    dd start                             ; AddressOfEntryPoint                ; VirtualAddress
    dd codesize                          ; BaseOfCode UNUSED                  ; SizeOfRawData
    dd start                             ; BaseOfData UNUSED                  ; PointerToRawData

;
; Import table (array of IMAGE_IMPORT_DESCRIPTOR structures)
;

idata:
    dd 0x400000                          ; ImageBase                          ; PointerToRelocations UNUSED ; OriginalFirstThunk UNUSED
    dd sectalign  ; e_lfanew             ; SectionAlignment                   ; PointerToLinenumbers UNUSED ; TimeDateStamp UNUSED
    dd filealign                         ; FileAlignment                      ; NumberOfRelocations UNUSED  ; ForwarderChain UNUSED
                                                                              ; NumberOfLinenumbers UNUSED
    dd kernel32                          ; MajorOperatingSystemVersion UNUSED ; Characteristics UNUSED      ; Name
                                         ; MinorOperatingSystemVersion UNUSED                               ; FirstThunk
    dd iat                               ; MajoirImageVersion UNUSED
                                         ; MinorImageVersion UNUSED
    dw 4                                 ; MajorSubsystemVersion                                            ; OriginalFirstThunk UNUSED
    dw 0                                 ; MinorSubsystemVersion UNUSED
    dd 0                                 ; Win32VersionValue UNUSED                                         ; TimeDateStamp UNUSED
    dd round(hdrsize, sectalign)+round(codesize,sectalign) ; SizeOfImage                                    ; ForwarderChain UNUSED
    dd round(hdrsize, filealign)         ; SizeOfHeaders                                                    ; Name UNUSED
    dd 0                                 ; CheckSum UNUSED                                                  ; FirstThunk

idatasize equ $ - idata

    dw 2                                 ; Subsystem (Win32 GUI)
    dw 0                                 ; DllCharacteristics UNUSED
    dd 0                                 ; SizeOfStackReserve
    dd 0                                 ; SizeOfStackCommit
    dd 0                                 ; SizeOfHeapReserve
    dd 0                                 ; SizeOfHeapCommit
;    dd 0                                 ; LoaderFlags UNUSED
;    dd 2                                 ; NumberOfRvaAndSizes

;
; The DLL name should be at most 16 bytes, including the null terminator
;

kernel32:
    db "KERNEL32.dll", 0

    times 16-($-kernel32) db 0

;
; Data directories
;
; The debug directory size at offset 0x34 from here must be 0

;    dd 0                                 ; Export Table UNUSED
;    dd 0

    db idata - $$                        ; Import Table

hdrsize equ $ - $$

codesize equ $ - start

filesize equ $ - $$
