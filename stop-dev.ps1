
[CmdletBinding()]
param(
    [ValidateRange(1, 600)]
    [int]$StopTimeoutSec = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = $PSScriptRoot

# Hash HARUS identik dengan start-dev.ps1 (algoritma SHA256, input repo-root
# yang di-lowercase, ambil 16 hex pertama) agar menunjuk file sesi yang sama.
# SHA256.HashData() bersifat statis dan hanya ada di .NET 5+; memakai
# SHA256.Create()/ComputeHash() yang kompatibel dengan .NET Framework/PowerShell 5.1.
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $hashBytes = $sha256.ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($RepoRoot.ToLowerInvariant())
    )
} finally {
    $sha256.Dispose()
}
$StateHash = [System.BitConverter]::ToString($hashBytes).Replace("-", "").Substring(0, 16).ToLowerInvariant()

# [System.IO.Path]::GetTempPath() dipakai agar sama persis dengan start-dev.ps1.
$DefaultStateFile = Join-Path ([System.IO.Path]::GetTempPath()) "repolens-dev-$StateHash.session.json"
$StateFile = if ($env:REPOLENS_DEV_STATE_FILE) {
    $env:REPOLENS_DEV_STATE_FILE
} else {
    $DefaultStateFile
}

function Get-ProcessIdentity {
    param([int]$ProcessId)

    try {
        $proc = Get-CimInstance Win32_Process `
            -Filter "ProcessId = $ProcessId" `
            -ErrorAction Stop

        if (-not $proc) {
            return $null
        }

        [pscustomobject]@{
            Name        = [string]$proc.Name
            Pid         = [int]$proc.ProcessId
            # StartTicks harus sepadan dengan yang ditulis start-dev.ps1
            # (CreationDate.Ticks), bukan representasi tanggal yang diformat.
            StartTicks  = [string]($proc.CreationDate.Ticks)
            CommandLine = [string]$proc.CommandLine
        }
    } catch {
        return $null
    }
}

function Test-VerifiedProcess {
    param($Record)

    $live = Get-ProcessIdentity -ProcessId ([int]$Record.Pid)

    if (-not $live) {
        return $false
    }

    return (
        $live.Name -eq [string]$Record.Image -and
        $live.StartTicks -eq [string]$Record.StartTicks -and
        $live.CommandLine -eq [string]$Record.CommandLine
    )
}

function Save-State {
    param($State)

    $json = ConvertTo-Json -InputObject $State -Depth 5
    Set-Content -LiteralPath $StateFile -Value $json -Encoding UTF8
}

function Get-ListeningPorts {
    $ports = @(8000, 5173)

    foreach ($port in $ports) {
        $connections = @(
            Get-NetTCPConnection -LocalPort $port -State Listen `
                -ErrorAction SilentlyContinue
        )

        foreach ($connection in $connections) {
            [pscustomobject]@{
                Port = $port
                Pid  = [int]$connection.OwningProcess
            }
        }
    }
}

Write-Host "`nRepoLens Development Shutdown" -ForegroundColor Cyan
Write-Host "Root: $RepoRoot"

if (-not (Test-Path -LiteralPath $StateFile -PathType Leaf)) {
    Write-Host "[WARN] Tidak ada catatan sesi RepoLens." -ForegroundColor Yellow

    $listeners = @(Get-ListeningPorts)
    if ($listeners.Count -gt 0) {
        Write-Host "[FAIL] Port development masih digunakan, tetapi proses tidak dapat diverifikasi." -ForegroundColor Red
        $listeners | Format-Table -AutoSize
        exit 1
    }

    Write-Host "[OK] Tidak ada port development yang sedang digunakan." -ForegroundColor Green
    exit 0
}

try {
    $raw = Get-Content -LiteralPath $StateFile -Raw
    $state = ConvertFrom-Json -InputObject $raw

    if ($null -eq $state) {
        throw "File sesi kosong atau tidak valid."
    }

    $records = @()
    if ($state -is [System.Array]) {
        $records = @($state)
    } elseif ($state.PSObject.Properties.Name -contains "Processes") {
        $records = @($state.Processes)
    } else {
        $records = @($state)
    }
} catch {
    Write-Host "[FAIL] Catatan sesi tidak dapat dibaca. File dipertahankan." -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit 1
}

$failed = $false

foreach ($record in $records) {
    if (-not $record.Pid -or -not $record.Image -or
        -not $record.StartTicks -or
        $null -eq $record.CommandLine) {
        Write-Host "[FAIL] Catatan proses tidak lengkap; tidak ada proses yang dihentikan." -ForegroundColor Red
        $failed = $true
        continue
    }

    $pidToStop = [int]$record.Pid

    if (-not (Test-VerifiedProcess -Record $record)) {
        $live = Get-ProcessIdentity -ProcessId $pidToStop

        if ($live) {
            Write-Host "[WARN] PID $pidToStop tidak cocok dengan identitas sesi; dilewati." -ForegroundColor Yellow
            $failed = $true
        } else {
            Write-Host "[INFO] PID $pidToStop sudah tidak berjalan."
        }

        continue
    }

    Write-Host "[STOP] Menghentikan $($record.Image), PID $pidToStop..."

    try {
        & taskkill.exe /PID $pidToStop /T /F | Out-Host

        if ($LASTEXITCODE -ne 0) {
            Write-Host "[FAIL] taskkill gagal untuk PID $pidToStop." -ForegroundColor Red
            $failed = $true
        }
    } catch {
        Write-Host "[FAIL] Tidak dapat menghentikan PID $pidToStop." -ForegroundColor Red
        $failed = $true
    }
}

$deadline = [DateTime]::UtcNow.AddSeconds($StopTimeoutSec)

do {
    $stillRunning = @(
        foreach ($record in $records) {
            if (Test-VerifiedProcess -Record $record) {
                [int]$record.Pid
            }
        }
    )

    $ports = @(Get-ListeningPorts)

    if ($stillRunning.Count -eq 0 -and $ports.Count -eq 0) {
        break
    }

    Start-Sleep -Milliseconds 500
} while ([DateTime]::UtcNow -lt $deadline)

if ($stillRunning.Count -gt 0 -or $ports.Count -gt 0) {
    Write-Host "[FAIL] Proses atau port masih aktif setelah batas waktu." -ForegroundColor Red

    if ($stillRunning.Count -gt 0) {
        Write-Host "PID yang masih berjalan: $($stillRunning -join ', ')"
    }

    if ($ports.Count -gt 0) {
        $ports | Format-Table -AutoSize
    }

    Write-Host "Catatan sesi dipertahankan untuk pemeriksaan berikutnya."
    exit 1
}

if ($failed) {
    Write-Host "[WARN] Port sudah kosong, tetapi ada proses yang tidak dapat diverifikasi." -ForegroundColor Yellow
    Write-Host "Periksa catatan sesi sebelum menghapusnya."
    exit 1
}

Remove-Item -LiteralPath $StateFile -Force

Write-Host "[OK] Backend dan frontend RepoLens telah dihentikan." -ForegroundColor Green
Write-Host "[OK] Port 8000 dan 5173 sudah tersedia." -ForegroundColor Green
