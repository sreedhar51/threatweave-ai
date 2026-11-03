# Publish this *new* project to a public GitHub repository.
# Requires GitHub CLI (gh), Git, and an authenticated GitHub session.
# Never embeds, echoes, or stores an access token.
$ErrorActionPreference = 'Stop'
$owner = 'sreedhar51'
$repo = 'threatweave-ai'
Set-Location (Join-Path $PSScriptRoot '..')
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw 'GitHub CLI (gh) is required. Install from https://cli.github.com/ then run gh auth login.' }
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'Git is required.' }
gh auth status | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'GitHub authentication is required. Run gh auth login.' }
$existing = gh repo view "$owner/$repo" --json name --jq .name 2>$null
if ($LASTEXITCODE -eq 0) { throw "Repository $owner/$repo already exists. Publishing stopped to avoid overwriting anything." }
if (-not (Test-Path '.git')) { git init -b main; if ($LASTEXITCODE -ne 0) { throw 'git init failed.' } }
git add .
if ($LASTEXITCODE -ne 0) { throw 'git add failed.' }
$changes = git status --porcelain
if ($changes) {
  git -c user.name='ThreatWeave Contributors' -c user.email='noreply@users.noreply.github.com' commit -m 'Initial ThreatWeave AI agent v0.1'
  if ($LASTEXITCODE -ne 0) { throw 'git commit failed.' }
}
gh repo create "$owner/$repo" --public --source . --remote origin --push --description 'Evidence-qualified vulnerability and CIS correlation with policy-driven decision replay'
if ($LASTEXITCODE -ne 0) { throw 'GitHub repository publication failed. Check gh authentication and permissions.' }
Write-Host "Published: https://github.com/$owner/$repo"
