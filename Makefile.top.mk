all:
	@echo "make configure"
	@echo "make build"

configure:
	./configure --prefix=$(HOME)/bin/tracegrind --enable-inner

run:
	#--smc-check=all-non-fil

build:
	make

.PHONY: configure build
