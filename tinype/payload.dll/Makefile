build: payload.dll test.exe
	@echo DLL file size:
	@echo `du -b payload.dll | cut -f 1` bytes
	@echo Running test.exe
	@./test.exe ; echo $$?

%.obj: %.c
	cl /nologo /c /O1 $<

payload.dll: payload.obj
	link /nologo /DLL /ENTRY:DllMain /EXPORT:DllMain,@1 /NODEFAULTLIB /SUBSYSTEM:WINDOWS /ALIGN:16 payload.obj user32.lib

test.exe: test.obj
	link /nologo /ENTRY:main /NODEFAULTLIB /SUBSYSTEM:WINDOWS /ALIGN:4 test.obj kernel32.lib user32.lib

clean:
	rm -rf payload.dll payload.exp payload.lib payload.obj test.exe test.obj

.PHONY: build clean
