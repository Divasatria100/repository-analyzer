<#Requires -Version 5.1
<#
.SYNOPSIS
  Menjalankan development environment RepoLens (frontend + backend).

.DESCRIPTION
  Menjalankan Vite dev server (frontend) dan Uvicorn (backend) sebagai dua
  proses terpisah secara bersamaan, memvalidasi prasyarat lebih dahulu, lalu
  menunggu kesiapan kedua layanan melalui endpoint yang sudah ada.

  - Tidak menginstal/memperbarui dependency, tidak mengubah konfigurasi proyek.
  - Tidak menjalankan migration, seed, analyzer, atau operasi database.
  - Tidak menjalankan kode dari repository GitHub yang dianalisis RepoLens;
    script ini hanya menjalankan layanan RepoLens sendiri.
  - Tidak menimpa file .env dan tidak menampilkan isi .env/secret.
  - Tidak mematikan proses lain: port yang sudah dipakai dilaporkan sebagai
    error (proses pemilik port tidak disentuh).
  - Hentikan dengan Ctrl+C — hanya proses milik script yang dihentikan.

  Backend Python dipilih dari backend/.venv bila tersedia. Bila tidak, script
  memakai `python` di PATH secara EKSPLISIT dan tetap memvalidasi versi Python
  (sesuai backend/pyproject.toml) dan dependency wajib sebelum menjalankan
  Uvicorn. `.env` bersifat opsional: nilai default aplikasi aman untuk
  development.

.PARAMETER FrontendPort
  Port Vite (default 5173, selaras frontend/vite.config.ts).

.PARAMETER BackendPort
  Port Uvicorn (default 8000).

.PARAMETER ReadyTimeoutSec
  Batas waktu tunggu kesiapan tiap layanan, dalam detik (default 90, minimum 5).

.PARAMETER SkipFrontend
  Jangan jalankan frontend.

.PARAMETER SkipBackend
  Jangan jalankan backend.

.EXAMPLE
  .\start-dev.ps1
  .\start-dev.ps1 -FrontendPort 5174 -BackendPort 8001
  .\start-dev.ps1 -SkipBackend
  .\start-dev.ps1 -SkipFrontend
  .\start-dev.ps1 -ReadyTimeoutSec 30
#>

[CmdletBinding()]
param(
  [int]$FrontendPort = 5173,
  [int]$BackendPort = 8000,
  [ValidateRange(5, 600)]
  [int]$ReadyTimeoutSec = 90,
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

# Proses yang diluncurkan script ini: nama, PID, dan image saat diluncurkan
# (image dipakai sebagai pengaman terhadap PID reuse sebelum dihentikan).
$script:children = @()

function Write-Check([string]$Message) { Write-Host "  [CHECK] $Message" -ForegroundColor Gray }
function Write-Start([string]$Message) { Write-Host "  [START] $Message" -ForegroundColor Cyan }
function Write-Wait([string]$Message)  { Write-Host "  [WAIT]  $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message)    { Write-Host "  [OK]    $Message" -ForegroundColor Green }
function Write-WarnMsg([string]$Message) { Write-Host "  [WARN]  $Message" -ForegroundColor Yellow }
function Write-FailMsg([string]$Message) { Write-Host "  [FAIL]  $Message" -ForegroundColor Red }
function Write-Detail([string]$Message)  { Write-Host "          $Message" -ForegroundColor DarkGray }

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

function Get-RequiredPythonVersion {
  param([string]$PyprojectPath)
  # Ikuti persyaratan aktual proyek daripada mengasumsikan versi.
  if (Test-Path -LiteralPath $PyprojectPath) {
    $match = Select-String -Path $PyprojectPath -Pattern 'requires-python\s*=\s*">=\s*([0-9]+)\.([0-9]+)'
    if ($match -ne $null -and $match.Matches.Count -gt 0) {
      $major = $match.Matches[0].Groups[1].Value
      $minor = $match.Matches[0].Groups[2].Value
      return [version]"$major.$minor"
    }
  }
  return $null
}

function Wait-EndpointReady {
  param(
    [string]$Url,
    [int]$TimeoutSec,
    [int[]]$AcceptStatus,
    [System.Diagnostics.Process]$Process
  )
  # Hasil: State = Ready | Exited | Timeout. Pemeriksaan HTTP (bukan sekadar
  # port) dipakai sebagai bukti kesiapan; proses yang mati saat startup
  # dideteksi lebih awal beserta exit code-nya.
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    if ($null -ne $Process) {
      try { $Process.Refresh() } catch { }
      if ($Process.HasExited) {
        return [pscustomobject]@{ State = "Exited"; ExitCode = $Process.ExitCode }
      }
    }
    try {
      $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
      $code = [int]$response.StatusCode
      if ($AcceptStatus -contains $code) {
        return [pscustomobject]@{ State = "Ready"; StatusCode = $code }
      }
    } catch {
      # Belum siap: koneksi ditolak, timeout, atau status non-2xx.
    }
    Start-Sleep -Milliseconds 500
  }
  return [pscustomobject]@{ State = "Timeout" }
}

function Stop-OwnProcesses {
  # Hanya menghentikan proses yang diluncurkan script ini (tree milik PID
  # tersebut). Proses lain di port yang sama TIDAK disentuh. Image name
  # diverifikasi agar PID yang sudah dipakai ulang oleh proses lain tidak
  # ikut dihentikan.
  if ($script:children.Count -eq 0) { return }
  foreach ($child in $script:children) {
    try {
      $process = Get-Process -Id $child.Pid -ErrorAction SilentlyContinue
      if ($process -eq $null) { continue }
      if ($process.ProcessName -ne $child.Image) {
        Write-WarnMsg "PID $($child.Pid) kini milik '$($process.ProcessName)', bukan '$($child.Image)' — dilewati."
        continue
      }
      Write-Detail "Menghentikan $($child.Name) (PID $($child.Pid))..."
      & taskkill /PID $child.Pid /T /F 2>$null | Out-Null
    } catch {
      # Proses sudah berhenti sendiri — tidak masalah.
    }
  }
  $script:children = @()
}

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " RepoLens Development Environment" -ForegroundColor Cyan
Write-Host " Root : $RepoRoot" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# ---------------- Keputusan layanan yang dijalankan ----------------
$wantFrontend = -not $SkipFrontend.IsPresent
$wantBackend = -not $SkipBackend.IsPresent

if ((-not $wantFrontend) -and (-not $wantBackend)) {
  Write-FailMsg "-SkipFrontend dan -SkipBackend diberikan bersamaan: tidak ada layanan untuk dijalankan."
  exit 1
}

# ---------------- [CHECK] Python environment (backend) ----------------
$backendPython = $null
$backendPythonLabel = $null

if ($wantBackend) {
  Write-Check "Python environment"
  if (-not (Test-Path -LiteralPath $BackendDir)) {
    Write-FailMsg "Direktori backend/ tidak ditemukan di $BackendDir."
    exit 1
  }

  $venvPython = Join-Path $BackendDir ".venv\Scripts\python.exe"
  if (Test-Path -LiteralPath $venvPython) {
    $backendPython = $venvPython
    $backendPythonLabel = "backend/.venv"
  } else {
    # Fallback eksplisit ke Python sistem. Venv tetap disarankan karena
    # dependensi global bisa berbeda dari yang diharapkan proyek.
    $systemPython = Get-Command "python" -ErrorAction SilentlyContinue
    if ($systemPython -eq $null) {
      Write-FailMsg "backend/.venv belum ada dan 'python' tidak ditemukan di PATH."
      Write-Detail "Buat virtual environment sesuai backend/README.md:"
      Write-Detail "  cd backend"
      Write-Detail "  python -m venv .venv"
      Write-Detail "  .\.venv\Scripts\Activate.ps1"
      Write-Detail "  pip install -e `".[dev]`""
      exit 1
    }
    $backendPython = $systemPython.Source
    $backendPythonLabel = "system python ('python' di PATH)"
    Write-WarnMsg "backend/.venv belum ada; memakai Python sistem secara eksplisit."
    Write-Detail "Disarankan membuat venv agar dependensi sesuai proyek:"
    Write-Detail "  cd backend; python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -e `".[dev]`""
  }

  # Versi Python harus memenuhi requires-python proyek.
  $requiredPython = Get-RequiredPythonVersion -PyprojectPath (Join-Path $BackendDir "pyproject.toml")
  $pythonVersionText = $null
  try {
    $pythonVersionText = (& $backendPython -c "import sys; print('%d.%d.%d' % sys.version_info[:3])" 2>$null | Select-Object -First 1)
  } catch {
    $pythonVersionText = $null
  }
  if ([string]::IsNullOrWhiteSpace($pythonVersionText)) {
    Write-FailMsg "Tidak dapat menjalankan Python terpilih: $backendPython"
    Write-Detail "Periksa bahwa interpreter valid (bukan stub Microsoft Store) atau buat backend/.venv."
    exit 1
  }
  if ($requiredPython -ne $null -and ([version]$pythonVersionText -lt $requiredPython)) {
    Write-FailMsg "Python $pythonVersionText terlalu lama; proyek membutuhkan >= $requiredPython."
    Write-Detail "Perbarui Python atau buat backend/.venv dengan interpretor yang memenuhi syarat."
    exit 1
  }
  Write-Detail "Interpreter : $backendPython"
  Write-Detail "Sumber      : $backendPythonLabel"
  Write-Detail "Versi       : $pythonVersionText"

  # Dependency wajib backend (backend/pyproject.toml [project].dependencies).
  $probe = "import uvicorn, fastapi, pydantic, pydantic_settings, sqlalchemy, alembic, httpx, jinja2, tree_sitter, psycopg"
  try {
    & $backendPython -c $probe 2>$null | Out-Null
    $depsOk = ($LASTEXITCODE -eq 0)
  } catch {
    $depsOk = $false
  }
  if (-not $depsOk) {
    Write-FailMsg "Dependency wajib backend tidak lengkap di: $backendPython"
    Write-Detail "Pasang sesuai backend/README.md, contoh:"
    Write-Detail "  cd backend; pip install -e `".[dev]`""
    exit 1
  }
  Write-Ok "Python environment siap ($backendPythonLabel)."
}

# ---------------- [CHECK] Backend configuration (.env) ----------------
if ($wantBackend) {
  Write-Check "Backend configuration"
  $envPath = Join-Path $BackendDir ".env"
  $envExamplePath = Join-Path $BackendDir ".env.example"
  if (Test-Path -LiteralPath $envPath) {
    Write-Ok "backend/.env ditemukan (isi tidak ditampilkan)."
  } elseif (Test-Path -LiteralPath $envExamplePath) {
    Write-WarnMsg "backend/.env belum ada — memakai konfigurasi default aplikasi (aman untuk development)."
    Write-Detail "Untuk menyesuaikan, salin contoh berikut lalu edit manual:"
    Write-Detail "  Copy-Item backend\.env.example backend\.env"
    Write-Detail "Script tidak membuat/menimpa .env secara otomatis."
  } else {
    Write-WarnMsg "backend/.env dan backend/.env.example tidak ada — memakai konfigurasi default aplikasi."
  }
}

# ---------------- [CHECK] Frontend dependencies ----------------
$npmCmd = $null
if ($wantFrontend) {
  Write-Check "Frontend dependencies"
  if (-not (Test-Path -LiteralPath $FrontendDir)) {
    Write-FailMsg "Direktori frontend/ tidak ditemukan di $FrontendDir."
    exit 1
  }
  if (-not (Test-Path -LiteralPath (Join-Path $FrontendDir "package.json"))) {
    Write-FailMsg "frontend/package.json tidak ditemukan."
    exit 1
  }

  $nodeCmd = Get-Command "node" -ErrorAction SilentlyContinue
  if ($nodeCmd -eq $null) {
    Write-FailMsg "Node.js tidak ditemukan di PATH."
    Write-Detail "Pasang Node.js (lihat frontend/README.md), lalu jalankan ulang script."
    exit 1
  }
  $npmCmd = (Get-Command "npm.cmd" -ErrorAction SilentlyContinue)
  if ($npmCmd -eq $null) {
    Write-FailMsg "npm tidak ditemukan di PATH."
    Write-Detail "Pasang npm bersama Node.js (lihat frontend/README.md), lalu jalankan ulang script."
    exit 1
  }
  $npmCmd = $npmCmd.Source

  $nodeModules = Join-Path $FrontendDir "node_modules"
  $depsInstalled = (Test-Path -LiteralPath $nodeModules) -and
    (Get-ChildItem -LiteralPath $nodeModules -Force -ErrorAction SilentlyContinue | Select-Object -First 1) -ne $null
  if (-not $depsInstalled) {
    $installHint = "npm install"
    if (Test-Path -LiteralPath (Join-Path $FrontendDir "package-lock.json")) {
      $installHint = "npm ci   # atau: npm install"
    }
    Write-FailMsg "Dependency frontend belum terpasang (frontend/node_modules kosong/tidak ada)."
    Write-Detail "Pasang sesuai frontend/README.md, contoh:"
    Write-Detail "  cd frontend; $installHint"
    Write-Detail "Script tidak menginstal dependency secara otomatis."
    exit 1
  }
  $nodeVersion = (& $nodeCmd.Source --version 2>$null | Select-Object -First 1)
  Write-Detail "Node.js : $nodeVersion"
  Write-Detail "npm     : $npmCmd"
  Write-Ok "Frontend dependencies terpasang."
}

# ---------------- Cek port (tidak mematikan proses lain) ----------------
Write-Check "Port availability"
if ($wantFrontend -and (Test-PortInUse -Port $FrontendPort)) {
  Write-FailMsg "Port $FrontendPort sudah digunakan proses lain."
  Write-Detail "Proses pemilik port tidak dihentikan. Ulangi dengan port lain, mis. -FrontendPort 5174."
  exit 1
}
if ($wantBackend -and (Test-PortInUse -Port $BackendPort)) {
  Write-FailMsg "Port $BackendPort sudah digunakan proses lain."
  Write-Detail "Proses pemilik port tidak dihentikan. Ulangi dengan port lain, mis. -BackendPort 8001."
  exit 1
}
Write-Ok "Port yang diminta tersedia."

Write-Host ""

# ---------------- Jalankan layanan + tunggu kesiapan ----------------
$startupOk = $false
$frontendProcess = $null
$backendProcess = $null

try {
  if ($wantFrontend) {
    Write-Start "Frontend (Vite) di $FrontendDir"
    $frontendProcess = Start-Process -FilePath $npmCmd `
      -ArgumentList "run", "dev", "--", "--port", "$FrontendPort", "--strictPort" `
      -WorkingDirectory $FrontendDir -NoNewWindow -PassThru
    $script:children += [pscustomobject]@{ Name = "frontend (vite)"; Pid = $frontendProcess.Id; Image = $frontendProcess.ProcessName }
    Write-Detail "PID $($frontendProcess.Id) -> $FrontendUrl"
  }

  if ($wantBackend) {
    Write-Start "Backend (Uvicorn) di $BackendDir"
    $backendProcess = Start-Process -FilePath $backendPython `
      -ArgumentList "-m", "uvicorn", "app.main:app", "--reload", "--port", "$BackendPort" `
      -WorkingDirectory $BackendDir -NoNewWindow -PassThru
    $script:children += [pscustomobject]@{ Name = "backend (uvicorn)"; Pid = $backendProcess.Id; Image = $backendProcess.ProcessName }
    Write-Detail "PID $($backendProcess.Id) -> $BackendUrl"
  }

  Write-Host ""

  # Tunggu kesiapan tiap layanan; proses yang mati saat startup dideteksi
  # lebih awal (exit code), dan timeout selalu terbatas.
  $frontendResult = $null
  $backendResult = $null

  if ($wantFrontend) {
    Write-Wait "Frontend readiness (timeout ${ReadyTimeoutSec}s)"
    $frontendResult = Wait-EndpointReady -Url $FrontendUrl -TimeoutSec $ReadyTimeoutSec `
      -AcceptStatus @(200..399) -Process $frontendProcess
  }

  if ($wantBackend) {
    Write-Wait "Backend health check (timeout ${ReadyTimeoutSec}s)"
    $backendResult = Wait-EndpointReady -Url $BackendHealthUrl -TimeoutSec $ReadyTimeoutSec `
      -AcceptStatus @(200) -Process $backendProcess
  }

  Write-Host ""

  # Diagnosis ketika ada layanan yang tidak siap.
  $failed = $false
  if ($wantFrontend -and $frontendResult.State -ne "Ready") {
    $failed = $true
    if ($frontendResult.State -eq "Exited") {
      Write-FailMsg "Frontend berhenti saat startup (exit code $($frontendResult.ExitCode))."
    } else {
      Write-FailMsg "Frontend tidak siap di $FrontendUrl dalam ${ReadyTimeoutSec} detik."
    }
    Write-Detail "Periksa output proses di atas; frontend/vite kemungkinan gagal build/konfigurasi."
  }
  if ($wantBackend -and $backendResult.State -ne "Ready") {
    $failed = $true
    if ($backendResult.State -eq "Exited") {
      Write-FailMsg "Backend berhenti saat startup (exit code $($backendResult.ExitCode))."
    } else {
      Write-FailMsg "Backend tidak siap di $BackendHealthUrl dalam ${ReadyTimeoutSec} detik."
    }
    Write-Detail "Periksa output proses di atas; kemungkinan konfigurasi tidak valid (fail-closed),"
    Write-Detail "dependency gagal di-import, database belum siap, atau port bermasalah."
  }

  if ($failed) {
    # Jangan mengumumkan sukses. finally akan membersihkan proses milik script.
    Write-Host ""
    Write-FailMsg "Startup gagal; menghentikan proses yang diluncurkan script."
  } else {
    $startupOk = $true
    if ($wantFrontend) { Write-Ok "Frontend: $FrontendUrl" }
    if ($wantBackend) {
      Write-Ok "Backend : $BackendUrl"
      Write-Ok "Health  : $BackendHealthUrl"
    }
    Write-Host ""
    Write-Host "Berjalan. Tekan Ctrl+C untuk menghentikan proses milik script ini." -ForegroundColor Cyan
    Write-Host "Catatan: log tiap layanan dialirkan langsung ke konsol ini (tidak dibuat file log terpisah)." -ForegroundColor DarkGray

    # Tunggu hingga SALAH SATU proses anak berhenti (mis. crash) atau Ctrl+C;
    # layanan yang berhenti tidak dibiarkan meninggalkan sisa proses lain.
    $stopped = $null
    while ($true) {
      foreach ($child in $script:children) {
        if (-not (Get-Process -Id $child.Pid -ErrorAction SilentlyContinue)) { $stopped = $child; break }
      }
      if ($stopped -ne $null) { break }
      Start-Sleep -Milliseconds 500
    }
    Write-Host ""
    Write-WarnMsg "$($stopped.Name) berhenti; menghentikan sisa proses milik script."
  }
} finally {
  Write-Host ""
  Stop-OwnProcesses
  Write-Host "Selesai." -ForegroundColor Cyan
}

if (-not $startupOk) { exit 1 }
exit 0
