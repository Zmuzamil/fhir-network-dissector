# FHIR network lab - one script for everything (Windows PowerShell).
#
#   .\netlab\lab.ps1 generate                  every scenario, 5 min each, then evaluate (~25 min)
#   .\netlab\lab.ps1 generate -Short           every scenario, 60 s each (~10 min)
#   .\netlab\lab.ps1 generate -Scenario icu,ward -Duration 120
#   .\netlab\lab.ps1 run -Scenario icu         one scenario: up + wait + down + evaluate
#   .\netlab\lab.ps1 up -Scenario ward         start one scenario and leave it running
#   .\netlab\lab.ps1 down                      stop it, merge the answer key (safe after an interrupted start)
#   .\netlab\lab.ps1 evaluate                  re-evaluate captures/netlab/ and write summary.txt
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet("generate", "run", "up", "down", "evaluate")][string]$Action,
    [string[]]$Scenario = @(),      # general | ward | laboratory | icu
    [int]$Duration = 300,           # client run time per scenario, seconds
    [switch]$Short                  # = -Duration 60
)
if ($Short) { $Duration = 60 }
$py = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
$ctl = Join-Path $PSScriptRoot "labctl.py"
switch ($Action) {
    "generate" { & $py $ctl generate @Scenario --duration $Duration }
    "evaluate" { & $py $ctl evaluate @Scenario }
    "down"     { & $py $ctl down }
    default {
        if ($Scenario.Count -ne 1) { Write-Error "$Action needs exactly one -Scenario"; exit 2 }
        & $py $ctl $Action $Scenario[0] --duration $Duration
    }
}
exit $LASTEXITCODE
