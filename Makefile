VERSION_FILE = src/ironscanner/version.txt
PYTHON ?= python3

build: build_py

build_c:

build_py: ${VERSION_FILE}
	echo "Building IronScanner"
	${PYTHON} ./setup.py build

${VERSION_FILE}:
	git describe --always >| $@

version: ${VERSION_FILE}

clean:
	rm -rf build dist
	rm -rf src/ironscanner.egg-info
	rm -f src/ironscanner/version.txt

doc:

check:
	flake8

test:

install: install_py

install_c:

install_py: ${VERSION_FILE}
	echo "Installing IronScanner"
	${PYTHON} ./setup.py install ${PIP_ARGS}

uninstall:
	echo "Uninstalling IronScanner"
	pip3 uninstall -y ironscanner

windows_exe:
	pyinstaller --noconfirm pyinstaller/win64.spec

linux_exe: install_py
	pyinstaller --noconfirm pyinstaller/linux.spec

release:
ifeq (${RELEASE}, )
	@echo "You must specify a release version (make release RELEASE=1.2.3)"
else
	@echo "Will release: ${RELEASE}"
	@echo "Checking release is in ChangeLog ..."
	grep ${RELEASE} ChangeLog
	@echo "Releasing ..."
	git tag -a ${RELEASE} -m ${RELEASE}
	git push origin ${RELEASE}
	@echo "All done"
endif

help:
	@echo "make build"
	@echo "make help: display this message"
	@echo "make install"
	@echo "make uninstall"
	@echo "make exe"

.PHONY: \
	build \
	build_c \
	build_py \
	check \
	doc \
	exe \
	help \
	install \
	install_c \
	install_py \
	release \
	test \
	uninstall \
	uninstall_c \
	version
