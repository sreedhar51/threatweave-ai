"""Offline CMDB-to-Tenable mapping *proposals*; never an identity auto-merge.

Only exact case-insensitive FQDN or hostname comparisons are offered. An analyst
must explicitly set mapping_verified=yes before the existing CMDB import can
associate a CI with an asset. IP addresses are never lookup keys.
"""
import csv
import ipaddress
import json
from collections import defaultdict
from pathlib import Path
from .ingest import iter_records


def _normalized_host(value):
    if not isinstance(value, str):
        return None
    host = value.strip().rstrip('.').casefold()
    if not host or any(ch.isspace() for ch in host):
        return None
    # Never allow a bare IP as a hostname; including IPv6 bracket literals.
    try:
        ipaddress.ip_address(host.strip('[]'))
        return None
    except ValueError:
        pass
    return host


def _ci_names(record):
    fqdn = _normalized_host(record.get('fqdn') or record.get('dns_name') or record.get('fully_qualified_domain_name'))
    name = _normalized_host(record.get('host_name') or record.get('hostname') or record.get('name'))
    # A ServiceNow CI may contain a qualified name in its 'name' field.
    if not fqdn and name and '.' in name:
        fqdn = name
    return fqdn if fqdn and '.' in fqdn else None, (name.split('.', 1)[0] if name else (fqdn.split('.',1)[0] if fqdn else None))


def propose_mappings(store, input_path, output_path):
    """Write reviewable proposals, preserving input columns plus mapping fields.

    Counts report mapping candidates, ambiguous hostnames and unmatched CIs,
    without asserting that any proposed identity has been verified.
    """
    fqdn_index, hostname_index = defaultdict(set), defaultdict(set)
    for asset in store.rows('SELECT asset_id,hostname FROM assets ORDER BY asset_id'):
        host = _normalized_host(asset.get('hostname'))
        if not host:
            continue
        if '.' in host:
            fqdn_index[host].add(asset['asset_id'])
        hostname_index[host.split('.',1)[0]].add(asset['asset_id'])

    originals = list(iter_records(input_path))
    columns = []
    for row in originals:
        if not isinstance(row, dict):
            raise ValueError('CMDB export must contain object rows')
        for key in row:
            if key not in columns:
                columns.append(key)
    for key in ('tenable_asset_uuid','match_method','mapping_verified'):
        if key not in columns:
            columns.append(key)

    counts = {'matched': 0, 'ambiguous': 0, 'unmatched': 0}
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        for original in originals:
            fqdn, hostname = _ci_names(original)
            candidates = fqdn_index.get(fqdn, set()) if fqdn else set()
            method = 'fqdn' if candidates else ''
            # Never downgrade an *ambiguous* exact FQDN to a weaker hostname.
            if not candidates and hostname:
                candidates = hostname_index.get(hostname, set())
                method = 'hostname' if candidates else ''
            row = dict(original)
            row['tenable_asset_uuid'] = ''
            row['match_method'] = ''
            row['mapping_verified'] = ''  # Only an analyst may approve.
            if len(candidates) == 1:
                row['tenable_asset_uuid'] = next(iter(candidates))
                row['match_method'] = method
                counts['matched'] += 1
            elif candidates:
                counts['ambiguous'] += 1
            else:
                counts['unmatched'] += 1
            # Preserve CSV/JSON input values without accidentally serializing Python lists.
            writer.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v
                             for k,v in row.items()})
    return {'source_file':str(input_path),'output_file':str(out),'received':len(originals),**counts,
            'approved':0,'note':'Review identity and mark mapping_verified=yes manually before import. IPs are never used.'}
