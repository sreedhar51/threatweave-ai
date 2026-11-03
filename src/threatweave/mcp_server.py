"""ThreatWeave read-only MCP tool surface (optional `pip install -e '.[mcp]'`).

Uses MCP Python SDK v2; v1 FastMCP fallback is provided for compatibility.
No tools modify Tenable, CMDB, security configurations, or source files.
"""
import os
from . import tools as core

try:
    from mcp.server import MCPServer
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer
    except ImportError:
        MCPServer=None

if MCPServer is not None:
    mcp=MCPServer('ThreatWeave AI Evidence Tools')

    def db():
        return os.getenv('THREATWEAVE_DB','runtime/threatweave.db')

    def policy_path():
        return os.getenv('THREATWEAVE_POLICY','policies/business-context.yaml')

    @mcp.tool()
    def get_security_overview() -> dict:
        """Overview of imported security assets, findings, compliance and context."""
        return core.overview(db())

    @mcp.tool()
    def list_fix_groups(limit: int=15) -> dict:
        """Return highest-priority candidate fix groups with source evidence references."""
        return core.list_fix_groups(db(),policy_path(),limit)

    @mcp.tool()
    def get_asset_exposure(asset_uuid: str) -> dict:
        """Inspect same-asset vulnerabilities, CIS failures and CMDB context; no network-path inference."""
        return core.retrieve_asset(db(),asset_uuid)

    @mcp.tool()
    def get_group_evidence(fix_group_id: str, limit: int=15) -> dict:
        """Fetch bounded source evidence for one candidate remediation group."""
        return core.retrieve_group_evidence(db(),fix_group_id,limit)

    @mcp.tool()
    def evaluate_policy_dry_run(policy: dict) -> dict:
        """Validate and evaluate a proposed policy without changing an active policy or Tenable data."""
        return core.preview_policy(db(),policy,limit=15)

    @mcp.tool()
    def compare_decision_receipts(before_path: str, after_path: str) -> dict:
        """Compare two trusted local Decision Receipt files; both paths remain local."""
        # Do not offer this tool on network-hosted MCP without safe path restriction.
        from pathlib import Path
        root=Path(os.getenv('THREATWEAVE_RECEIPTS','runtime/receipts')).resolve()
        def constrain(p):
            resolved=Path(p).resolve()
            if root!=resolved and root not in resolved.parents:
                raise ValueError('Receipt paths must be inside configured receipts directory')
            return str(resolved)
        return core.compare_receipt_files(constrain(before_path),constrain(after_path))
else:
    mcp=None


def main():
    if mcp is None:
        raise RuntimeError("MCP SDK not installed. Run: pip install -e '.[mcp]'")
    mcp.run()

if __name__=='__main__':
    main()
