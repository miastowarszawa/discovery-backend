# Redis optional patch

Ten patch robi dwie rzeczy:

1. Dodaje `redis` do `requirements.txt`.
2. Uodparnia `app/db/session.py` na świeże środowisko bez zainstalowanego pakietu `redis`.

## Zalecany krok teraz

    python -m pip install redis

albo pełniej:

    python -m pip install -r requirements.txt

## Zachowanie po patchu

- testy, które override'ują `get_redis`, nie wyłożą się już na samym imporcie modułu,
- prawdziwy Redis będzie wymagany dopiero wtedy, gdy aplikacja faktycznie spróbuje użyć `get_redis()`.
