build: tiny.exe tiny.dump
	@echo File size:
	@echo `du -b tiny.exe | cut -f 1` bytes
	@echo Running tiny.exe
	@./tiny.exe ; echo $$?

tiny.dump: tiny.exe
	dumpbin /ALL /RAWDATA:NONE tiny.exe > tiny.dump

tiny.exe: tiny.obj
	link /nologo tiny.obj

tiny.obj: tiny.c
	cl /nologo /c tiny.c 

clean:
	rm -rf tiny.exe tiny.obj tiny.dump

.PHONY: build clean
