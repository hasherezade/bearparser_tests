build: tiny.exe
	@echo File size:
	@echo `du -b tiny.exe | cut -f 1` bytes
	@echo Running tiny.exe
	@./tiny.exe ; echo $$?

tiny.exe: tiny.asm
	nasm -f bin -o tiny.exe tiny.asm && chmod 755 tiny.exe

clean:
	rm -rf tiny.exe

.PHONY: build clean
