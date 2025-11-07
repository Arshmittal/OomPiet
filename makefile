VENV := venv
PYTHON := python
PIP := $(VENV)/Scripts/pip
ACTIVATE := $(VENV)/Scripts/activate

.PHONY: venv install clean shell

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

shell: install
	powershell -NoExit -Command ".\$(ACTIVATE)"

clean:
	rmdir /S /Q $(VENV)
