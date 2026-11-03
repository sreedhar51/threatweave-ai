"""Optional columnar Parquet staging for high-volume analytical workloads.

The base application uses SQLite so it works without native DuckDB/PyArrow wheels.
Install `[analytics]` for Parquet materialization and DuckDB analytical queries.
"""
from pathlib import Path

TABLES=('assets','findings','cmdb','correlations')


def export_parquet(store,directory,chunk_size=10000):
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError("Install analytics extra: pip install -e '.[analytics]'") from exc
    directory=Path(directory)
    directory.mkdir(parents=True,exist_ok=True)
    result={}
    for table in TABLES:
        cursor=store.db.execute(f'SELECT * FROM {table}')
        cols=[x[0] for x in cursor.description]
        path=directory/(table+'.parquet')
        writer=None
        count=0
        try:
            while True:
                rows=cursor.fetchmany(chunk_size)
                if not rows:break
                batch=pa.Table.from_pylist([dict(zip(cols,row)) for row in rows])
                if writer is None: writer=pq.ParquetWriter(str(path),batch.schema)
                writer.write_table(batch)
                count+=len(rows)
        finally:
            if writer is not None:writer.close()
        if writer is None:
            schema=pa.schema([pa.field(c,pa.string()) for c in cols])
            pq.write_table(pa.Table.from_pylist([],schema=schema),str(path))
        result[table]={'rows':count,'file':str(path)}
    return result


def duckdb_group_summary(parquet_directory):
    try:import duckdb
    except ImportError as exc:
        raise RuntimeError("Install analytics extra: pip install -e '.[analytics]'") from exc
    path=Path(parquet_directory)/'findings.parquet'
    db=duckdb.connect(':memory:')
    try:
        return db.execute('''SELECT kind, severity, COUNT(*) AS finding_count,
                             COUNT(DISTINCT asset_id) AS affected_assets
                             FROM read_parquet(?) GROUP BY 1,2 ORDER BY 1,2''',[str(path)]).fetchall()
    finally:db.close()
