#!/usr/bin/env bash
set -euo pipefail

source venv/bin/activate

# formata código
black .

# checa erros comuns (inclui indentação e NameError)
ruff check .

# valida compilação
python3 -m py_compile soc_ti.py

# executa
python3 soc_ti.py
