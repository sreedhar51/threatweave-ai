"""Explicit UI dataset boundaries. Never point synthetic loaders at tenant DBs."""
from pathlib import Path
import json
from .store import Store
from .fixtures import load_demo
from .ingest import ingest_records
from .correlate import correlate



def tenant_database_choices(root, configured=None):
    """Discover existing local tenant DB files without creating any database.

    Synthetic fixture databases are excluded. An explicitly configured path can
    be outside runtime but must exist, be a file and not be a synthetic source.
    """
    root=Path(root).resolve()
    runtime=(root/'runtime').resolve()
    excluded={(runtime/'demo.db').resolve(), (runtime/'enterprise-demo.db').resolve()}
    staged=(runtime/'staged-ui').resolve()
    configured_path=Path(configured).expanduser().resolve() if configured else None
    if configured_path and (configured_path in excluded or configured_path.parent==staged):
        raise ValueError('THREATWEAVE_DB cannot select a synthetic demonstration database')
    if configured_path and (not configured_path.is_file() or configured_path.suffix.lower()!='.db'):
        raise ValueError('THREATWEAVE_DB must point to an existing tenant SQLite .db file')
    candidates=[]
    if runtime.is_dir():
        candidates=[p.resolve() for p in runtime.glob('*.db') if p.is_file() and not p.is_symlink()
                    and p.resolve() not in excluded]
    if configured_path and configured_path not in candidates:
        candidates.append(configured_path)
    choices=sorted(set(candidates),key=lambda p:(0 if configured_path and p==configured_path
                                               else 1 if p.name=='tenant-lab.db'
                                               else 2,p.name.lower(),str(p)))
    return choices


def source_paths(root, tenant_db):
    root=Path(root).resolve()
    tenant=Path(tenant_db).resolve()
    demo=(root/'runtime/demo.db').resolve()
    enterprise=(root/'runtime/enterprise-demo.db').resolve()
    stages={name:(root/'runtime/staged-ui'/(name+'.db')).resolve() for name in (
        'stage1_vulnerabilities','stage2_plus_cis','stage3_plus_cmdb')}
    if tenant in {demo,enterprise,*stages.values()}:
        raise ValueError('Tenant DB cannot overlap a synthetic demonstration database')
    return {'Tenant':tenant, 'Synthetic demo':demo,
            'Enterprise demo':enterprise, 'Staged demo':stages}


def load_synthetic_isolated(root, tenant_db):
    locations=source_paths(root,tenant_db)
    demo=Store(locations['Synthetic demo'])
    try:
        reports=load_demo(demo)
        correlate(demo,Path(root)/'policies/correlation-rules.yaml')
        return reports
    finally:
        demo.close()


def load_enterprise_synthetic_isolated(root, tenant_db):
    """Build the fictional five-asset showcase in an isolated, replaceable DB.

    Never write to a tenant DB; validate all records and recompute same-asset links.
    """
    locations=source_paths(root,tenant_db)
    path=locations['Enterprise demo']
    path.parent.mkdir(parents=True,exist_ok=True)
    fixture=json.loads((Path(root)/'examples/enterprise-context-demo.json').read_text(encoding='utf-8'))
    # Use a temporary database so incomplete imports cannot replace the good demo.
    import os
    import tempfile
    fd,name=tempfile.mkstemp(prefix='enterprise-',suffix='.db',dir=str(path.parent))
    os.close(fd)
    temp=Path(name)
    try:
        store=Store(temp)
        try:
            reports=[]
            for kind,key in [('asset','assets'),('vulnerability','vulnerability'),
                             ('compliance','compliance'),('cmdb','cmdb')]:
                report=ingest_records(store,fixture[key],kind,'synthetic-enterprise')
                if report['rejected']:
                    raise ValueError(f'Synthetic enterprise {kind} import rejected {report["rejected"]}')
                reports.append(report)
            correlate(store,Path(root)/'policies/correlation-rules.yaml')
        finally:
            store.close()
        os.replace(temp,path)
        return reports
    finally:
        if temp.exists():
            temp.unlink()
