import pytest
from sqlalchemy import text


@pytest.mark.asyncio
async def test_duplicate_check_query_detects_duplicates(db_session, target):
    await db_session.execute(
        text(
            """
            INSERT INTO asset (id, target_id, asset_type, value, source, attributes)
            VALUES
            (:id1, :target_id, 'host', 'dup.example.com', 'seed', '{{}}'),
            (:id2, :target_id, 'host', 'dup.example.com', 'seed', '{{}}')
            """
        ),
        {
            'id1': '11111111-1111-1111-1111-111111111111',
            'id2': '22222222-2222-2222-2222-222222222222',
            'target_id': str(target.id),
        },
    )
    await db_session.commit()

    result = await db_session.execute(
        text(
            """
            SELECT target_id, asset_type, value, COUNT(*) AS cnt
            FROM asset
            GROUP BY target_id, asset_type, value
            HAVING COUNT(*) > 1
            LIMIT 1
            """
        )
    )
    row = result.fetchone()

    assert row is not None
    assert row.cnt == 2
