build: tiny.exe tiny.dump
	@echo File size:
	@echo `du -b tiny.exe | cut -f 1` bytes
	@echo Running tiny.exe
	@./tiny.exe ; echo $$?

tiny.dump: tiny.exe
	dumpbin /ALL /RAWDATA:NONE /DISASM tiny.exe > tiny.dump

tiny.exe: tiny.asm
	nasm -f bin -o tiny.exe tiny.asm && chmod 755 tiny.exe

clean:
	rm -rf tiny.exe tiny.dump

.PHONY: build clean
