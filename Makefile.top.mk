all:
	@echo "make configure"
	@echo "make build"

configure:
	./configure --prefix=$(HOME)/bin/tracegrind --enable-inner

build:
	make

.PHONY: configure build
