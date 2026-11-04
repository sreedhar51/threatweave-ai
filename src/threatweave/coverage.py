"""Indexed aggregate evidence-coverage queries, without fetching individual findings."""


def evidence_coverage(store):
    families = store.rows(
        "SELECT COALESCE(NULLIF(software_family,''),'unclassified') AS family, "
        "COUNT(*) AS count FROM findings WHERE kind='vulnerability' "
        "GROUP BY COALESCE(NULLIF(software_family,''),'unclassified') ORDER BY count DESC, family")
    compliance = store.rows(
        "SELECT upper(coalesce(status,'UNKNOWN')) AS status, COUNT(*) AS count "
        "FROM findings WHERE kind='compliance' "
        "GROUP BY upper(coalesce(status,'UNKNOWN')) ORDER BY status")
    cmdb = store.db.execute(
        "SELECT COUNT(*) AS total, "
        "COALESCE(SUM(CASE WHEN verified=1 AND asset_id IS NOT NULL THEN 1 ELSE 0 END),0) AS verified "
        "FROM cmdb").fetchone()
    correlations = store.rows(
        "SELECT rule_id, COUNT(*) AS count FROM correlations GROUP BY rule_id ORDER BY count DESC, rule_id")
    asset_sources = store.rows(
        "SELECT coalesce(source,'unknown') AS source,COUNT(*) AS count "
        "FROM assets GROUP BY coalesce(source,'unknown') ORDER BY count DESC")
    finding_sources = store.rows(
        "SELECT coalesce(source,'unknown') AS source,COUNT(*) AS count "
        "FROM findings GROUP BY coalesce(source,'unknown') ORDER BY count DESC")
    return {
        'software_families':families,
        'unclassified_vulnerabilities':next((r['count'] for r in families if r['family']=='unclassified'),0),
        'compliance_status':compliance,
        'cmdb':{'total':cmdb['total'],'verified':cmdb['verified'],
                'unverified':cmdb['total']-cmdb['verified']},
        'correlation_rules':correlations,
        'asset_sources':asset_sources,
        'finding_sources':finding_sources
    }
