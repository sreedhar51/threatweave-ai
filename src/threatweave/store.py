"""Local read-model: source records remain distinct and queryable by evidence ID."""
import json
import sqlite3
from pathlib import Path
from .utils import canonical, digest

DDL = """
CREATE TABLE IF NOT EXISTS assets (
 asset_id TEXT PRIMARY KEY, hostname TEXT, os TEXT, asset_type TEXT,
 environment TEXT, role TEXT, tags_json TEXT, source TEXT, raw_hash TEXT,
 last_seen TEXT
);
CREATE TABLE IF NOT EXISTS findings (
 finding_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, kind TEXT NOT NULL,
 source TEXT NOT NULL, title TEXT, severity TEXT, vpr REAL, plugin_id TEXT,
 port TEXT, protocol TEXT, cves_json TEXT, status TEXT, observed_at TEXT,
 solution TEXT, software_family TEXT, control_id TEXT, expected_value TEXT,
 actual_value TEXT, audit_file TEXT, source_hash TEXT, source_excerpt TEXT
);
CREATE INDEX IF NOT EXISTS idx_f_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_f_kind ON findings(kind);
CREATE TABLE IF NOT EXISTS cmdb (
 ci_id TEXT PRIMARY KEY, asset_id TEXT, verified INTEGER, business_service TEXT,
 criticality TEXT, environment TEXT, role TEXT, support_group TEXT,
 business_tags_json TEXT, internet_exposure TEXT, observed_at TEXT,
 source_hash TEXT
);
CREATE INDEX IF NOT EXISTS idx_c_asset ON cmdb(asset_id);
CREATE TABLE IF NOT EXISTS correlations (
 correlation_id TEXT PRIMARY KEY, asset_id TEXT NOT NULL,
 vuln_id TEXT NOT NULL, compliance_id TEXT NOT NULL, rule_id TEXT NOT NULL,
 rationale TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_runs (
 run_id TEXT PRIMARY KEY, provider TEXT, record_type TEXT, total INTEGER,
 accepted INTEGER, rejected INTEGER, report_json TEXT
);
"""

class Store:
    def __init__(self, path="runtime/threatweave.db"):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(DDL)

    def close(self):
        self.db.close()

    def rows(self, sql, params=()):
        return [dict(r) for r in self.db.execute(sql, params).fetchall()]

    def count(self, table):
        if table not in {"assets", "findings", "cmdb", "correlations"}:
            raise ValueError("invalid table")
        return self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0]

    def upsert_asset(self, r):
        # Re-importing an asset must not erase previously known attributes with nulls.
        self.db.execute("""INSERT INTO assets VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(asset_id) DO UPDATE SET
           hostname=COALESCE(excluded.hostname,assets.hostname),
           os=COALESCE(excluded.os,assets.os),
           asset_type=COALESCE(excluded.asset_type,assets.asset_type),
           environment=COALESCE(excluded.environment,assets.environment),
           role=COALESCE(excluded.role,assets.role),
           tags_json=CASE WHEN excluded.tags_json != '[]' THEN excluded.tags_json ELSE assets.tags_json END,
           source=excluded.source,raw_hash=excluded.raw_hash,
           last_seen=COALESCE(excluded.last_seen,assets.last_seen)""",
           (r["asset_id"],r.get("hostname"),r.get("os"),r.get("asset_type"),
            r.get("environment"),r.get("role"), canonical(r.get("tags") or []),
            r.get("source"),r.get("raw_hash"),r.get("last_seen")))

    def upsert_finding(self, r):
        cols = ("finding_id","asset_id","kind","source","title","severity","vpr","plugin_id",
                "port","protocol","cves_json","status","observed_at","solution","software_family",
                "control_id","expected_value","actual_value","audit_file","source_hash","source_excerpt")
        vals = [canonical(r.get("cves") or []) if c=="cves_json" else r.get(c) for c in cols]
        self.db.execute(f"INSERT OR REPLACE INTO findings ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",vals)

    def upsert_cmdb(self, r):
        cols=("ci_id","asset_id","verified","business_service","criticality","environment","role",
              "support_group","business_tags_json","internet_exposure","observed_at","source_hash")
        vals=[canonical(r.get("business_tags") or []) if c=="business_tags_json" else r.get(c) for c in cols]
        self.db.execute(f"INSERT OR REPLACE INTO cmdb ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",vals)

    def commit(self):
        self.db.commit()

    def snapshot_hash(self):
        """Canonical data fingerprint, stable across insertion order; excludes ingest timestamps."""
        h = __import__('hashlib').sha256()
        for table, cols, key in [
            ("assets",("asset_id","hostname","os","asset_type","environment","role","tags_json","source","raw_hash","last_seen"),"asset_id"),
            ("findings",("finding_id","asset_id","kind","source","title","severity","vpr","plugin_id","port","protocol","cves_json","status","observed_at","solution","software_family","control_id","expected_value","actual_value","audit_file","source_hash"),"finding_id"),
            ("cmdb",("ci_id","asset_id","verified","business_service","criticality","environment","role","support_group","business_tags_json","internet_exposure","observed_at","source_hash"),"ci_id"),
            ("correlations",("correlation_id","asset_id","vuln_id","compliance_id","rule_id","rationale"),"correlation_id")]:
            h.update(table.encode())
            for row in self.db.execute(f"SELECT {','.join(cols)} FROM {table} ORDER BY {key}"):
                h.update(canonical(tuple(row)).encode())
        return h.hexdigest()

    def input_fingerprints(self):
        """Stable per-input digests; same columns as snapshot_hash, partitioned by source.

        These hashes track evidence changes, not the correctness of source data.
        """
        import hashlib
        specs = (
            ('assets', 'assets', ('asset_id','hostname','os','asset_type','environment','role','tags_json','source','raw_hash','last_seen'), 'asset_id', None),
            ('vulnerabilities', 'findings', ('finding_id','asset_id','kind','source','title','severity','vpr','plugin_id','port','protocol','cves_json','status','observed_at','solution','software_family','control_id','expected_value','actual_value','audit_file','source_hash'), 'finding_id', 'vulnerability'),
            ('compliance', 'findings', ('finding_id','asset_id','kind','source','title','severity','vpr','plugin_id','port','protocol','cves_json','status','observed_at','solution','software_family','control_id','expected_value','actual_value','audit_file','source_hash'), 'finding_id', 'compliance'),
            ('cmdb', 'cmdb', ('ci_id','asset_id','verified','business_service','criticality','environment','role','support_group','business_tags_json','internet_exposure','observed_at','source_hash'), 'ci_id', None),
            ('correlations', 'correlations', ('correlation_id','asset_id','vuln_id','compliance_id','rule_id','rationale'), 'correlation_id', None),
        )
        result = {}
        for label,table,columns,key,kind in specs:
            h = hashlib.sha256()
            h.update(label.encode('utf-8'))
            sql = f"SELECT {','.join(columns)} FROM {table}"
            args = ()
            if kind is not None:
                sql += ' WHERE kind=?'
                args = (kind,)
            sql += f' ORDER BY {key}'
            for row in self.db.execute(sql,args):
                h.update(canonical(tuple(row)).encode('utf-8'))
            result[label] = 'sha256:' + h.hexdigest()
        return result

    def overview(self):
        result = {t:self.count(t) for t in ("assets","findings","cmdb","correlations")}
        result["types"] = self.rows("SELECT kind,count(*) AS count FROM findings GROUP BY kind ORDER BY kind")
        return result
