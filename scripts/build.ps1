<#
  VirtDetect - build portatile e autosufficiente.

  Scarica la stessa toolchain usata da CindyLooper (winlibs GCC 16.2.0,
  UCRT, x64) dentro .tools\, compila con windres + gcc e lascia
  dist\VirtDetect.exe. Nessuna installazione di sistema, nessuna modifica
  permanente al PATH, nessun privilegio di amministratore.

  Uso:
    .\scripts\build.ps1                 build Release
    .\scripts\build.ps1 -BuildType Debug
    .\scripts\build.ps1 -SetupOnly      scarica solo la toolchain
    .\scripts\build.ps1 -Force          riscarica e reinstallla la toolchain
    .\scripts\build.ps1 -GccPath C:\...\mingw64\bin
    .\scripts\build.ps1 -Test           esegue l'exe al termine
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$BuildType = 'Release',

    [switch]$SetupOnly,
    [switch]$Force,
    [switch]$Test,

    [string]$GccPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$ToolsDir   = Join-Path $RepoRoot '.tools'
$CacheDir   = Join-Path $RepoRoot '.cache'
$DownloadDir = Join-Path $CacheDir 'downloads'
$DistDir    = Join-Path $RepoRoot 'dist'
$ObjDir     = Join-Path $RepoRoot 'obj'

# Toolchain fissata: stessa versione usata da CindyLooper.
# Per aggiornarla servono URL, nome file e SHA-256 nuovi.
$Gcc = [pscustomobject]@{
    Name    = 'winlibs GCC'
    Version = '16.2.0 (posix-seh, UCRT, x64)'
    Url     = 'https://github.com/brechtsanders/winlibs_mingw/releases/download/16.2.0posix-23.1.3-14.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-16.2.0-mingw-w64ucrt-14.0.0-r3.zip'
    File    = 'winlibs-gcc-16.2.0-mingw-w64ucrt-14.0.0.zip'
    Sha256  = '3c69305081e4a647144339a936244fcf7d3d9e558319e1ad7be2cd2886d4b6a1'
    Dir     = 'mingw64'
}

function Write-Step([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-RemoteFile([string]$Url, [string]$Path) {
    $part = "$Path.part"
    if (Test-Path -LiteralPath $part) {
        Remove-Item -LiteralPath $part -Force
    }
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source -L --fail --retry 3 --retry-delay 2 -o $part $Url
        if ($LASTEXITCODE -ne 0) {
            throw "Download fallito: $Url"
        }
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $part -UseBasicParsing
    }
    Move-Item -LiteralPath $part -Destination $Path -Force
}

function Expand-ZipRoot([string]$Zip, [string]$Dest) {
    $tmp = Join-Path $CacheDir ('tmp-' + [IO.Path]::GetFileNameWithoutExtension($Zip))
    if (Test-Path -LiteralPath $tmp) {
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null

    $systemTar = Join-Path $env:SystemRoot 'System32\tar.exe'
    if (Test-Path -LiteralPath $systemTar) {
        & $systemTar -xf $Zip -C $tmp
        if ($LASTEXITCODE -ne 0) {
            throw "Estrazione fallita: $Zip"
        }
    } else {
        Expand-Archive -LiteralPath $Zip -DestinationPath $tmp -Force
    }

    $entries = @(Get-ChildItem -LiteralPath $tmp -Force)
    $source = $tmp
    if ($entries.Count -eq 1 -and $entries[0].PSIsContainer) {
        $source = $entries[0].FullName
    }

    if (Test-Path -LiteralPath $Dest) {
        Remove-Item -LiteralPath $Dest -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Dest) | Out-Null
    Move-Item -LiteralPath $source -Destination $Dest
    if (Test-Path -LiteralPath $tmp) {
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
}

function Install-Toolchain {
    New-Item -ItemType Directory -Force -Path $ToolsDir, $DownloadDir, $DistDir, $ObjDir | Out-Null

    $dest = Join-Path $ToolsDir $Gcc.Dir
    $gccExe = Join-Path $dest 'bin\gcc.exe'

    if (-not $Force -and (Test-Path -LiteralPath $gccExe)) {
        Write-Step "$($Gcc.Name) $($Gcc.Version) gia' presente in .tools\$($Gcc.Dir)"
        return $gccExe
    }

    $archive = Join-Path $DownloadDir $Gcc.File
    $needDownload = $Force -or -not (Test-Path -LiteralPath $archive)

    if (-not $needDownload) {
        Write-Step 'verifica SHA-256 dell archivio gia scaricato'
        if ((Get-FileSha256 $archive) -ne $Gcc.Sha256) {
            Write-Warning 'Archivio corrotto o di versione diversa: lo riscarico.'
            Remove-Item -LiteralPath $archive -Force
            $needDownload = $true
        }
    }

    if ($needDownload) {
        Write-Step "download $($Gcc.Name) $($Gcc.Version) (~264 MB)"
        Get-RemoteFile $Gcc.Url $archive
        $hash = Get-FileSha256 $archive
        Write-Host "    sha256 $hash"
        if ($hash -ne $Gcc.Sha256) {
            Remove-Item -LiteralPath $archive -Force
            throw "SHA-256 non corrispondente. Download interrotto."
        }
    }

    Write-Step "estrazione in .tools\$($Gcc.Dir) (~950 MB su disco)"
    Expand-ZipRoot $archive $dest

    if (-not (Test-Path -LiteralPath $gccExe)) {
        throw "gcc.exe non trovato dopo l'estrazione: $gccExe"
    }
    return $gccExe
}

function Resolve-Toolchain {
    if ($GccPath) {
        $exe = $GccPath
        if (Test-Path -LiteralPath $GccPath -PathType Container) {
            $exe = Join-Path $GccPath 'gcc.exe'
        }
        if (-not (Test-Path -LiteralPath $exe)) {
            throw "gcc.exe non trovato in -GccPath: $GccPath"
        }
        Write-Step "uso toolchain esterna: $exe"
        return (Split-Path -Parent $exe)
    }
    return (Split-Path -Parent (Install-Toolchain))
}

function Invoke-Build([string]$MingwBin) {
    $gccExe     = Join-Path $MingwBin 'gcc.exe'
    $windresExe = Join-Path $MingwBin 'windres.exe'

    if (-not (Test-Path -LiteralPath $gccExe)) {
        throw "gcc non trovato: $gccExe"
    }
    if (-not (Test-Path -LiteralPath $windresExe)) {
        throw "windres non trovato: $windresExe"
    }

    Write-Step "compilazione ($BuildType)"
    New-Item -ItemType Directory -Force -Path $ObjDir, $DistDir | Out-Null

    $rcFile = Join-Path $RepoRoot 'res\VirtDetect.rc'
    $rcObj  = Join-Path $ObjDir 'VirtDetect.res'
    & $windresExe -I (Join-Path $RepoRoot 'res') -O coff -i $rcFile -o $rcObj
    if ($LASTEXITCODE -ne 0) {
        throw 'Compilazione delle risorse fallita.'
    }

    $sources = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'src') -Filter '*.c' -File |
                 Sort-Object Name |
                 ForEach-Object { $_.FullName })

    $flags = @(
        '-std=c17',
        '-finput-charset=UTF-8',
        '-fexec-charset=UTF-8',
        '-Wall', '-Wextra', '-Wno-unused-parameter'
    )
    if ($BuildType -eq 'Debug') {
        $flags += @('-O0', '-g')
    } else {
        $flags += @('-O2', '-s', '-DNDEBUG')
    }

    $exe = Join-Path $DistDir 'VirtDetect.exe'
    if (Test-Path -LiteralPath $exe) {
        Remove-Item -LiteralPath $exe -Force
    }

    $compileArgs = $flags + $sources + @($rcObj, '-o', $exe,
        '-liphlpapi', '-ladvapi32', '-luser32', '-lm',
        '-static', '-static-libgcc',
        '-Wl,--dynamicbase', '-Wl,--nxcompat')

    & $gccExe @compileArgs
    if ($LASTEXITCODE -ne 0) {
        throw 'Compilazione fallita.'
    }

    if (-not (Test-Path -LiteralPath $exe)) {
        throw "Eseguibile atteso mancante: $exe"
    }

    $objdump = Join-Path $MingwBin 'objdump.exe'
    if (Test-Path -LiteralPath $objdump) {
        $imports = & $objdump -p $exe |
            Select-String -Pattern 'DLL Name:\s*(\S+)' |
            ForEach-Object { $_.Matches[0].Groups[1].Value } |
            Sort-Object -Unique
        $runtime = @('libgcc_s_seh-1.dll', 'libwinpthread-1.dll', 'libstdc++-6.dll')
        $missing = @($imports | Where-Object { $runtime -contains $_ })
        if ($missing.Count -gt 0) {
            Write-Warning ('Il binario dipende da DLL runtime non incluse: ' +
                           ($missing -join ', '))
        }
        if ($imports.Count -gt 0) {
            Write-Host ('    import: ' + ($imports -join ', '))
        }
    }

    $size = [math]::Round((Get-Item -LiteralPath $exe).Length / 1KB)
    Write-Step "fatto: dist\VirtDetect.exe ($size KB)"

    if ($Test) {
        Write-Step 'esecuzione di prova'
        & $exe --no-color
        Write-Host "    codice di uscita: $LASTEXITCODE"
    }
}

# ------------------------------------------------------------------- main
$mingwBin = Resolve-Toolchain

& (Join-Path $mingwBin 'gcc.exe') --version | Select-Object -First 1

if ($SetupOnly) {
    Write-Step 'setup completato'
    return
}

Invoke-Build $mingwBin
