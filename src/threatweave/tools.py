"""Bounded, deterministic capabilities shared by the CLI, agent, and MCP server."""
import json
from pathlib import Path
from .store import Store
from .engine import rank_groups,create_receipt,compare_receipts,evidence_for_group
from .correlate import get_asset_exposure
from .policy import load_policy,validate_policy


def overview(db_path):
    store=Store(db_path)
    try:return store.overview()
    finally:store.close()


def list_fix_groups(db_path,policy_path,limit=20):
    store=Store(db_path)
    try:return {'groups':rank_groups(store,load_policy(policy_path),max_groups=max(1,min(50,int(limit))))}
    finally:store.close()


def retrieve_asset(db_path,asset_uuid):
    store=Store(db_path)
    try:return get_asset_exposure(store,asset_uuid,limit=50)
    finally:store.close()


def retrieve_group_evidence(db_path,fix_group_id,limit=20):
    store=Store(db_path)
    try:return evidence_for_group(store,fix_group_id,limit)
    finally:store.close()


def preview_policy(db_path,policy,limit=12):
    validate_policy(policy)
    store=Store(db_path)
    try:
        receipt=create_receipt(store,policy)
        return {'receipt_id':receipt['receipt_id'],'policy_hash':receipt['policy_hash'],
                'dataset_hash':receipt['dataset_hash'],'top_groups':receipt['rankings'][:max(1,min(30,int(limit)))],
                'not_activated':True}
    finally:store.close()


def compare_receipt_files(file_a,file_b,limit=20):
    return compare_receipts(json.loads(Path(file_a).read_text()),json.loads(Path(file_b).read_text()),limit)
