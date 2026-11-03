# Publishing ThreatWeave AI to GitHub

Intended new public repository: `sreedhar51/threatweave-ai`.

This project **has not been published** unless that URL is accessible and the source files are visible there. Avoid checking in `.env`, real Tenable exports, live databases, customer data, or authentication tokens.

## PowerShell (Windows)

1. Install Git and [GitHub CLI](https://cli.github.com/).
2. Authenticate to GitHub using `gh auth login` in your own terminal. Do not paste tokens into chat.
3. Extract the source ZIP and open PowerShell in the `threatweave-ai` folder.
4. Run `./scripts/publish_github.ps1`.
5. Verify the public repository at `https://github.com/sreedhar51/threatweave-ai`.

The script refuses to overwrite an existing repository with the same name and only commits non-ignored files. Review the files before publishing.

## After publication

- Enable GitHub Actions and check the CI test run.
- Verify no secrets or real vulnerability data appear in Git history.
- Install optional dependencies, validate the live Tenable connector with an authorized tenant, and test Streamlit/MCP/Claude integrations before claiming full feature support.
- Follow the official Exchange submission/eligibility instructions independently of creating this GitHub repository.
