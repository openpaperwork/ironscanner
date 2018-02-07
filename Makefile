build: src/ironscanner/version.txt
	echo "Building IronScanner"
	python3 ./setup.py build

src/ironscanner/version.txt:
	git describe --always >| $@

clean:
	rm -f src/ironscanner/version.txt

install: build
	echo "Installing IronScanner"
	python3 ./setup.py install ${PIP_ARGS}

uninstall: clean
	echo "Uninstalling IronScanner"
	pip3 uninstall -y ironscanner

exe:
	pyinstaller pyinstaller/ironscanner.spec

help:
	@echo "make build"
	@echo "make help: display this message"
	@echo "make install"
	@echo "make uninstall"
	@echo "make exe"

.PHONY: help build install uninstall exe
