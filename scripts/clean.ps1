<#
  VirtDetect - pulizia.

  Gruppi:
    binari    -> dist\, obj\
    toolchain -> .tools\, .cache\

  Uso:
    .\scripts\clean.ps1               interattivo (una domanda per gruppo)
    .\scripts\clean.ps1 -Binaries     solo output compilati
    .\scripts\clean.ps1 -Tools        solo toolchain e cache
    .\scripts\clean.ps1 -All          tutto
    .\scripts\clean.ps1 -All -WhatIf  mostra cosa verrebbe eliminato
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Binaries,
    [switch]$Tools,
    [switch]$All
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$targets = @{
    Binaries = @('dist', 'obj')
    Tools    = @('.tools', '.cache')
}

function Get-Size([string]$Path) {
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
    if ($null -eq $sum) { return 0 }
    return [long]$sum
}

function Remove-Group([string]$Label, [string[]]$RelativePaths) {
    $found = @()
    foreach ($rel in $RelativePaths) {
        $full = Join-Path $RepoRoot $rel
        if (Test-Path -LiteralPath $full) {
            $found += $full
        }
    }
    if ($found.Count -eq 0) {
        Write-Host "==> ${Label}: niente da eliminare"
        return
    }

    $total = 0
    foreach ($f in $found) { $total += Get-Size $f }
    $mb = [math]::Round($total / 1MB, 1)
    $done = $false
    foreach ($f in $found) {
        if ($PSCmdlet.ShouldProcess($f, "Elimina ($Label)")) {
            Remove-Item -LiteralPath $f -Recurse -Force
            $done = $true
        }
    }
    if ($done) {
        Write-Host "==> ${Label} eliminati ($mb MB)"
    } else {
        Write-Host "==> ${Label} da eliminare ($mb MB)"
    }
}

function Ask([string]$Question) {
    Write-Host -NoNewline "$Question [s/N] "
    $answer = Read-Host
    return ($answer -match '^(s|si|sì|y|yes)$')
}

if ($All) {
    Remove-Group 'binari' $targets.Binaries
    Remove-Group 'toolchain' $targets.Tools
    return
}

$doBinaries = $Binaries
$doTools = $Tools
if (-not $Binaries -and -not $Tools) {
    $doBinaries = Ask 'Eliminare i binari compilati (dist, obj)?'
    $doTools = Ask 'Eliminare la toolchain portatile (.tools, .cache)?'
}

if ($doBinaries) { Remove-Group 'binari' $targets.Binaries }
if ($doTools)    { Remove-Group 'toolchain' $targets.Tools }
