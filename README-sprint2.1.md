# Sprint 2.1 patch

Ten patch dopina scaffold Sprint 2 do działającej aplikacji.

## Zmiany

- `app/db/session.py` dodaje `redis_client` i dependency `get_redis`
- `app/main.py` podpina router skanów
- `app/services/recon_pipeline.py` obsługuje status `failed` oraz event `recon.failed`
- `tests/integration/test_scans_start.py` testuje `POST /api/v1/scans/start`
- `tests/integration/test_recon_failure.py` testuje ścieżkę błędu workera

## Po wklejeniu

    cd backend
    python -m pytest tests/integration -q
