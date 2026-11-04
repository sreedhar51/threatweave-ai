"""Explicit UI dataset boundaries. Never point synthetic loaders at tenant DBs."""
from pathlib import Path
from .store import Store
from .fixtures import load_demo
from .correlate import correlate


def source_paths(root, tenant_db):
    root=Path(root).resolve()
    tenant=Path(tenant_db).resolve()
    demo=(root/'runtime/demo.db').resolve()
    stages={name:(root/'runtime/staged-ui'/(name+'.db')).resolve() for name in (
        'stage1_vulnerabilities','stage2_plus_cis','stage3_plus_cmdb')}
    if tenant in {demo,*stages.values()}:
        raise ValueError('Tenant DB cannot overlap a synthetic demonstration database')
    return {'Tenant':tenant, 'Synthetic demo':demo, 'Staged demo':stages}


def load_synthetic_isolated(root, tenant_db):
    locations=source_paths(root,tenant_db)
    demo=Store(locations['Synthetic demo'])
    try:
        reports=load_demo(demo)
        correlate(demo,Path(root)/'policies/correlation-rules.yaml')
        return reports
    finally:
        demo.close()
