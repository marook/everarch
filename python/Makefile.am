TESTS = evr-test

EVR_INSTALL_EXEC_HOOKS =

if ENABLE_PYTHON_INSTALL_SYSTEM
EVR_INSTALL_EXEC_HOOKS += pip-install-system
endif

.PHONY: pip-install-system
pip-install-system:
	pip install . --no-deps --break-system-packages

.PHONY: install-exec-hook
install-exec-hook: $(EVR_INSTALL_EXEC_HOOKS)
