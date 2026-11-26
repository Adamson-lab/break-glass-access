run:  ; python3 app/breakglass.py
demo: ; python3 scripts/demo.py 2>&1 | grep -v '"siem"'
test: ; python3 -m unittest -v tests/test_breakglass.py
up:   ; docker compose up --build
