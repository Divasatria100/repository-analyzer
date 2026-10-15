<#Requires -Version 5.1
<#
.SYNOPSIS
  Menjalankan development environment RepoLens (frontend + backend).

.DESCRIPTION
  Menjalankan Vite dev server (frontend) dan Uvicorn (backend) sebagai dua
  proses terpisah secara bersamaan, lalu memantau status startup keduanya.

  - Tidak menginstal dependency, tidak mengubah konfigurasi proyek.
  - Tidak menjalankan migration, seed, analyzer, atau operasi database.
  - Tidak mematikan proses lain: port yang sudah dipakai hanya dilaporkan.
  - Hentikan dengan Ctrl+C — hanya proses milik script yang dihentikan.

.EXAMPLE
  .\start-dev.ps1
  .\start-dev.ps1 -FrontendPort 5174 -BackendPort 8001
  .\start-dev.ps1 -SkipBackend   # hanya frontend
  .\start-dev.ps1 -SkipFrontend  # hanya backend
#>

[CmdletBinding()]
param(
  [int]$FrontendPort = 5173,
  [int]$BackendPort = 8000,
  [switch]$SkipFrontend,
  [switch]$SkipBackend
)

$ErrorActionPreference = "Stop"

# Selalu relatif terhadap lokasi file ini, bukan direktori pemanggil.
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$FrontendDir = Join-Path $RepoRoot "frontend"
$BackendDir = Join-Path $RepoRoot "backend"

$FrontendUrl = "http://localhost:$FrontendPort"
$BackendUrl = "http://localhost:$BackendPort"
$BackendHealthUrl = "$BackendUrl/api/health"

$script:children = @()

function Write-Step([string]$Message) {
  Write-Host ""
  Write-Host "==> $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
  Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-WarnMsg([string]$Message) {
  Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Write-FailMsg([string]$Message) {
  Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

function Test-PortInUse {
  param([int]$Port)
  # Periksa IPv4 dan IPv6 secara terpisah: listener hanya di satu stack
  # (mis. vite di [::1]) tetap membuat bind gagal, tetapi tak terlihat dari
  # 127.0.0.1 saja. Soket IPv4 default tidak dapat menyentuh alamat IPv6
  # (AddressFamily mismatch), jadi tiap stack memakai soketnya sendiri.
  $targets = @(
    @{ Address = "127.0.0.1"; Family = [Net.Sockets.AddressFamily]::InterNetwork },
    @{ Address = "::1"; Family = [Net.Sockets.AddressFamily]::InterNetworkV6 }
  )
  foreach ($target in $targets) {
    $client = $null
    try {
      $client = New-Object Net.Sockets.TcpClient($target.Family)
      $handle = $client.BeginConnect($target.Address, $Port, $null, $null)
      $connected = $handle.AsyncWaitHandle.WaitOne(500)
      if ($connected -and $client.Connected) {
        return $true
      }
    } catch {
      # Stack tidak tersedia atau alamat tak terjangkau — lanjutkan.
    } finally {
      if ($client -ne $null) { $client.Close() }
    }
  }
  return $false
}

function Wait-HttpOk {
  param([string]$Url, [int]$TimeoutSec = 60)
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    try {
      $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
      if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
        return $true
      }
    } catch {
      Start-Sleep -Seconds 2
    }
  }
  return $false
}

function Stop-OwnProcesses {
  # Hanya menghentikan proses yang dilacak script ini (tree milik PID
  # tersebut). Proses lain di port yang sama TIDAK disentuh.
  foreach ($child in $script:children) {
    try {
      $process = Get-Process -Id $child.Pid -ErrorAction SilentlyContinue
      if ($process -ne $null) {
        Write-Host "  Menghentikan $($child.Name) (PID $($child.Pid))..."
        & taskkill /PID $child.Pid /T /F 2>$null | Out-Null
      }
    } catch {
      # Proses sudah berhenti sendiri — tidak masalah.
    }
  }
  $script:children = @()
}

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " RepoLens dev environment" -ForegroundColor Cyan
Write-Host " Root : $RepoRoot"
Write-Host "===============================================" -ForegroundColor Cyan

# ---------- Prasyarat: frontend ----------
$runFrontend = (-not $SkipFrontend.IsPresent) -and (Test-Path -LiteralPath $FrontendDir)
if (-not (Test-Path -LiteralPath $FrontendDir)) {
  Write-WarnMsg "Direktori frontend/ tidak ditemukan — frontend dilewati."
} elseif ($SkipFrontend.IsPresent) {
  Write-WarnMsg "Frontend dilewati sesuai flag -SkipFrontend."
} else {
  if (-not (Test-Path -LiteralPath (Join-Path $FrontendDir "package.json"))) {
    Write-WarnMsg "frontend/package.json tidak ditemukan — frontend dilewati."
    $runFrontend = $false
  } elseif (-not (Test-Path -LiteralPath (Join-Path $FrontendDir "node_modules"))) {
    Write-WarnMsg "frontend/node_modules belum ada. Jalankan 'npm install' di folder frontend/ terlebih dahulu — frontend dilewati (tidak menginstal otomatis)."
    $runFrontend = $false
  } else {
    $npmCmd = Get-Command "npm.cmd" -ErrorAction SilentlyContinue
    if ($npmCmd -eq $null) {
      Write-WarnMsg "npm tidak ditemukan di PATH — frontend dilewati."
      $runFrontend = $false
    }
  }
}

# ---------- Prasyarat: backend ----------
$runBackend = (-not $SkipBackend.IsPresent) -and (Test-Path -LiteralPath $BackendDir)
$backendPython = $null
if (-not (Test-Path -LiteralPath $BackendDir)) {
  Write-WarnMsg "Direktori backend/ tidak ditemukan — backend dilewati."
} elseif ($SkipBackend.IsPresent) {
  Write-WarnMsg "Backend dilewati sesuai flag -SkipBackend."
} else {
  $venvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
  if (Test-Path -LiteralPath $venvPython) {
    $backendPython = $venvPython
    Write-Ok "Menggunakan virtual environment backend/.venv"
  } else {
    $systemPython = Get-Command "python" -ErrorAction SilentlyContinue
    if ($systemPython -eq $null) {
      Write-WarnMsg "Python tidak ditemukan di PATH dan backend/.venv belum ada — backend dilewati."
      $runBackend = $false
    } else {
      $backendPython = $systemPython.Source
      Write-WarnMsg "backend/.venv belum ada; memakai system python. Jika dependency backend belum terpasang, buat venv sesuai backend/README.md — script tidak menginstal otomatis."
    }
  }
  if ($runBackend) {
    try {
      & $backendPython -c "import uvicorn" 2>$null
      if ($LASTEXITCODE -ne 0) { throw "uvicorn tidak tersedia" }
    } catch {
      Write-WarnMsg "Paket 'uvicorn' tidak tersedia di Python yang dipilih ($backendPython) — backend dilewati."
      $runBackend = $false
    }
  }
  if ($runBackend -and -not (Test-Path -LiteralPath (Join-Path $BackendDir ".env"))) {
    Write-WarnMsg "backend/.env belum ada (contoh: backend/.env.example). Server dijalankan dengan konfigurasi default; salin .env.example ke .env bila diperlukan."
  }
}

if ((-not $runFrontend) -and (-not $runBackend)) {
  Write-FailMsg "Tidak ada komponen yang dapat dijalankan. Periksa peringatan di atas."
  exit 1
}

# ---------- Cek port (tidak pernah mematikan proses lain) ----------
if ($runFrontend -and (Test-PortInUse -Port $FrontendPort)) {
  Write-WarnMsg "Port $FrontendPort sudah digunakan proses lain — frontend dilewati (proses lain tidak dihentikan)."
  $runFrontend = $false
}
if ($runBackend -and (Test-PortInUse -Port $BackendPort)) {
  Write-WarnMsg "Port $BackendPort sudah digunakan proses lain — backend dilewati (proses lain tidak dihentikan)."
  $runBackend = $false
}

if ((-not $runFrontend) -and (-not $runBackend)) {
  Write-FailMsg "Semua port yang diminta sudah terisi. Bebaskan port atau ulangi dengan -FrontendPort / -BackendPort lain."
  exit 1
}

# ---------- Jalankan proses ----------
try {
  if ($runFrontend) {
    Write-Step "Menjalankan frontend (Vite) di $FrontendDir"
    $npmCmd = (Get-Command "npm.cmd").Source
    $frontendProcess = Start-Process -FilePath $npmCmd `
      -ArgumentList "run", "dev", "--", "--port", "$FrontendPort", "--strictPort" `
      -WorkingDirectory $FrontendDir -NoNewWindow -PassThru
    $script:children += @{ Name = "frontend (vite)"; Pid = $frontendProcess.Id }
    Write-Host "  Frontend PID: $($frontendProcess.Id) -> $FrontendUrl"
  }

  if ($runBackend) {
    Write-Step "Menjalankan backend (Uvicorn) di $BackendDir"
    $backendProcess = Start-Process -FilePath $backendPython `
      -ArgumentList "-m", "uvicorn", "app.main:app", "--reload", "--port", "$BackendPort" `
      -WorkingDirectory $BackendDir -NoNewWindow -PassThru
    $script:children += @{ Name = "backend (uvicorn)"; Pid = $backendProcess.Id }
    Write-Host "  Backend PID : $($backendProcess.Id) -> $BackendUrl"
  }

  # ---------- Status startup ----------
  if ($runFrontend) {
    Write-Step "Menunggu frontend di $FrontendUrl ..."
    if (Wait-HttpOk -Url $FrontendUrl -TimeoutSec 90) {
      Write-Ok "Frontend aktif: $FrontendUrl"
    } else {
      Write-FailMsg "Frontend tidak merespons di $FrontendUrl dalam 90 detik. Periksa output di atas; proses tetap berjalan atau sudah berhenti sendiri."
    }
  }

  if ($runBackend) {
    Write-Step "Menunggu backend di $BackendHealthUrl ..."
    if (Wait-HttpOk -Url $BackendHealthUrl -TimeoutSec 90) {
      Write-Ok "Backend aktif : $BackendUrl (health: $BackendHealthUrl)"
      Write-Host "  Frontend memanggil backend di $BackendUrl (VITE_API_BASE_URL atau fallback default)."
    } else {
      Write-FailMsg "Backend tidak merespons di $BackendHealthUrl dalam 90 detik. Kemungkinan: database belum siap, konfigurasi tidak valid (backend fail-closed saat startup), atau port bermasalah. Periksa output di atas; tidak ada migration/seed yang dijalankan script ini."
    }
  }

  Write-Host ""
  Write-Host "Berjalan. Tekan Ctrl+C untuk menghentikan proses milik script ini." -ForegroundColor Cyan

  # Tunggu hingga semua proses anak berhenti (atau pengguna menekan Ctrl+C).
  $procs = @()
  foreach ($child in $script:children) {
    $process = Get-Process -Id $child.Pid -ErrorAction SilentlyContinue
    if ($process -ne $null) { $procs += $process }
  }
  if ($procs.Count -gt 0) {
    Wait-Process -Id ($procs | ForEach-Object { $_.Id })
  }
} finally {
  Write-Host ""
  Write-Host "Membersihkan proses milik script..." -ForegroundColor Cyan
  Stop-OwnProcesses
  Write-Host "Selesai."
}
