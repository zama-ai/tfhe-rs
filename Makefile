SHELL:=$(shell /usr/bin/env which bash)
RS_TOOLCHAIN:=$(shell cat toolchain.txt)
CARGO_RS_TOOLCHAIN:=+$(RS_TOOLCHAIN)

.PHONY: rs_toolchain # Echo the used rust toolchain for checks
rs_toolchain:
	@echo $(RS_TOOLCHAIN)

.PHONY: install_rs_toolchain # Install the toolchain used for checks
install_rs_toolchain:
	rustup toolchain install "$(RS_TOOLCHAIN)"

.PHONY: fmt # Format rust code
fmt:
	cargo "$(CARGO_RS_TOOLCHAIN)" fmt

.PHONT: check_fmt # Check rust code format
check_fmt:
	cargo "$(CARGO_RS_TOOLCHAIN)" fmt --check

.PHONY: help # Generate list of targets with descriptions
help:
	@grep '^.PHONY: .* #' Makefile | sed 's/\.PHONY: \(.*\) # \(.*\)/\1\t\2/' | expand -t30 | sort
