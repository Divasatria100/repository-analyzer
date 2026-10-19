<#Requires -Version 5.1
<#
.SYNOPSIS
  Menjalankan development environment RepoLens (frontend + backend).

.DESCRIPTION
  Menjalankan Vite dev server (frontend) dan Uvicorn (backend) sebagai dua
  proses terpisah secara bersamaan, memvalidasi prasyarat lebih dahulu, lalu
  menunggu kesiapan kedua layanan melalui endpoint yang sudah ada.

  - Tidak menginstal/memperbarui dependency, tidak mengubah konfigurasi proyek.
  - Memastikan service PostgreSQL RepoLens dari Docker Compose berjalan dan
    siap menerima koneksi sebelum backend/frontend dimulai. Script hanya
    menjalankan service `postgres` yang sudah didefinisikan; container atau
    layanan lain tidak disentuh.
  - Tidak menjalankan migration, seed, atau analyzer.
  - Tidak menjalankan kode dari repository GitHub yang dianalisis RepoLens;
    script ini hanya menjalankan layanan RepoLens sendiri.
  - Tidak menimpa file .env dan tidak menampilkan isi .env/secret.
  - Safe restart: bila sesi RepoLens sebelumnya (diluncurkan script ini) masih
    aktif, prosesnya dihentikan SETELAH diverifikasi milik RepoLens
    (PID + image + waktu mulai + command line), lalu script menunggu proses
    berhenti dan port tersedia sebelum memulai sesi baru. Bila sebuah proses
    tidak dapat diverifikasi atau tidak dapat dihentikan dengan aman, script
    berhenti dengan FAIL tanpa menyentuh proses asing.
  - Tidak mematikan proses lain: proses pemilik port yang tidak terverifikasi
    milik RepoLens dilaporkan sebagai error dan tidak disentuh.
  - Hentikan dengan Ctrl+C — hanya proses milik script yang dihentikan.

  State sesi disimpan di direktori temp (per-repo, tidak mengotori repo).
  Variabel lingkungan REPOLENS_DEV_STATE_FILE dapat menunjuk lokasi state lain
  (mis. untuk pengujian); verifikasi kepemilikan tetap berlaku.

  Backend Python dipilih dari backend/.venv bila tersedia. Bila tidak, script
  memakai `python` di PATH secara EKSPLISIT dan tetap memvalidasi versi Python
  (sesuai backend/pyproject.toml) dan dependency wajib sebelum menjalankan
  Uvicorn. `.env` diperlukan bila PostgreSQL lokal tidak memakai kredensial
  default aplikasi; lihat backend/.env.example. Jalankan
  `alembic upgrade head` sekali sebelum backend host memakai database baru.

.PARAMETER FrontendPort
  Port Vite (default 5173, selaras frontend/vite.config.ts).

.PARAMETER BackendPort
  Port Uvicorn (default 8000).

.PARAMETER ReadyTimeoutSec
  Batas waktu tunggu kesiapan tiap layanan, dalam detik (default 90, minimum 5).

.PARAMETER PostgresReadyTimeoutSec
  Batas waktu tunggu PostgreSQL RepoLens siap menerima koneksi, dalam detik
  (default 60, minimum 5). Hanya dipakai saat backend akan dijalankan.

.PARAMETER StopTimeoutSec
  Batas waktu tunggu agar proses sesi sebelumnya berhenti dan port menjadi
  bebas sebelum sesi baru dimulai, dalam detik (default 20, minimum 1).

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
  .\start-dev.ps1 -PostgresReadyTimeoutSec 120
  .\start-dev.ps1 -StopTimeoutSec 10
#>

[CmdletBinding()]
param(
  [int]$FrontendPort = 5173,
  [int]$BackendPort = 8000,
  [ValidateRange(5, 600)]
  [int]$ReadyTimeoutSec = 90,
  [ValidateRange(5, 600)]
  [int]$PostgresReadyTimeoutSec = 60,
  [ValidateRange(1, 300)]
  [int]$StopTimeoutSec = 20,
  [switch]$SkipFrontend,
  [switch]$SkipBackend
)

$ErrorActionPreference = "Stop"

# Selalu relatif terhadap lokasi file ini, bukan direktori pemanggil.
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$FrontendDir = Join-Path $RepoRoot "frontend"
$BackendDir = Join-Path $RepoRoot "backend"
$ComposeFile = Join-Path $RepoRoot "docker-compose.yml"
$script:ComposeFile = $ComposeFile
$script:RepoRoot = $RepoRoot

$FrontendUrl = "http://localhost:$FrontendPort"
$BackendUrl = "http://localhost:$BackendPort"
$BackendHealthUrl = "$BackendUrl/api/health"

# Sesi RepoLens: record proses yang diluncurkan script ini (nama, PID, image,
# waktu mulai, command line). State ini dimuat dari sesi sebelumnya dan
# diperbarui setiap kali proses diluncurkan, sehingga sesi baru dapat
# mengidentifikasi dan menghentikan proses RepoLens yang masih tertinggal.
# Image, waktu mulai, dan command line dipakai untuk memverifikasi kepemilikan
# serta sebagai pengaman terhadap PID reuse sebelum proses dihentikan.
$script:Session = @()
$script:StateFilePath = $null

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

function Get-SessionStatePath {
  # Path state sesi stabil per-repo, disimpan di direktori temp (bukan di repo)
  # supaya tidak mengotori working tree. Repo yang sama selalu memakai path
  # yang sama, sehingga sesi berikutnya dapat menemukan sesi sebelumnya.
  # REPOLENS_DEV_STATE_FILE dapat dipakai untuk memindahkan lokasi state
  # (mis. pengujian) tanpa mengubah perilaku verifikasi kepemilikan.
  if (-not [string]::IsNullOrWhiteSpace($env:REPOLENS_DEV_STATE_FILE)) {
    return $env:REPOLENS_DEV_STATE_FILE
  }
  $root = $RepoRoot
  if ([string]::IsNullOrWhiteSpace($root)) { $root = (Get-Location).Path }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($root.ToLowerInvariant()))
  } finally {
    $sha.Dispose()
  }
  $hex = -join ($bytes | ForEach-Object { $_.ToString("x2") })
  return (Join-Path ([System.IO.Path]::GetTempPath()) "repolens-dev-$($hex.Substring(0, 16)).session.json")
}

function Get-SessionRecords {
  # Normalisasi daftar record sesi (aman terhadap $null maupun record tunggal).
  # Pemanggil selalu membungkus hasilnya dengan @(...) agar .Count andal
  # meskipun hanya ada satu record.
  return @($script:Session | Where-Object { $null -ne $_ })
}

function Read-SessionState {
  # State sesi tidak dianggap sebagai sumber kebenaran tunggal: setiap record
  # tetap diverifikasi ulang (identitas proses) sebelum dipakai.
  $path = $script:StateFilePath
  if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) { return @() }
  try {
    $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    $parsed = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    if ($null -eq $parsed) { return @() }
    return @($parsed)
  } catch {
    Write-WarnMsg "State sesi sebelumnya tidak dapat dibaca ($path) — diabaikan."
    return @()
  }
}

function Save-SessionState {
  # Tulis state sesi; bila tidak ada record tersisa, state dihapus.
  $path = $script:StateFilePath
  if ([string]::IsNullOrWhiteSpace($path)) { return }
  $records = @(Get-SessionRecords)
  try {
    if ($records.Count -eq 0) {
      if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction Stop }
      return
    }
    $json = ConvertTo-Json -InputObject ([object[]]$records) -Depth 6
    Set-Content -LiteralPath $path -Value $json -Encoding UTF8 -ErrorAction Stop
  } catch {
    Write-WarnMsg "State sesi tidak dapat disimpan ($path): $($_.Exception.Message)"
  }
}

function Get-ProcessIdentity {
  param([int]$ProcessId)
  # Identitas proses untuk verifikasi kepemilikan + pengaman PID reuse.
  # $null berarti proses tidak ada (atau identitasnya tidak dapat dibaca).
  $cim = $null
  try {
    $cim = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction Stop
  } catch {
    return $null
  }
  if ($null -eq $cim) { return $null }
  $ticks = $null
  try { $ticks = $cim.CreationDate.Ticks } catch { $ticks = $null }
  return [pscustomobject]@{
    Pid         = [int]$cim.ProcessId
    Image       = $cim.Name
    StartTicks  = $ticks
    CommandLine = $cim.CommandLine
  }
}

function Test-ProcessRecordMatches {
  param($Record, $Identity)
  # Verifikasi bahwa PID pada record masih menunjuk proses yang SAMA, bukan
  # hasil PID reuse: image, waktu mulai (ticks), dan command line harus cocok.
  # Bila identitas tidak lengkap, record dianggap TIDAK terverifikasi (fail-safe).
  if ($null -eq $Record -or $null -eq $Identity) { return $false }
  if ([int]$Record.Pid -ne [int]$Identity.Pid) { return $false }
  if ([string]::IsNullOrWhiteSpace($Record.Image) -or [string]$Record.Image -ne [string]$Identity.Image) { return $false }
  if ($null -eq $Record.StartTicks -or $null -eq $Identity.StartTicks) { return $false }
  if ([string]$Record.StartTicks -ne [string]$Identity.StartTicks) { return $false }
  if (-not [string]::IsNullOrWhiteSpace($Record.CommandLine) -and
      -not [string]::IsNullOrWhiteSpace($Identity.CommandLine) -and
      $Record.CommandLine -ne $Identity.CommandLine) {
    return $false
  }
  return $true
}

function New-SessionRecord {
  param(
    [string]$Name,
    [System.Diagnostics.Process]$Process
  )
  # Rekam identitas proses yang baru diluncurkan. Identitas dibaca beberapa
  # kali karena proses (mis. wrapper npm) baru terbaca setelah beberapa saat.
  $identity = $null
  for ($attempt = 0; $attempt -lt 10 -and $null -eq $identity; $attempt++) {
    $identity = Get-ProcessIdentity -ProcessId $Process.Id
    if ($null -eq $identity) { Start-Sleep -Milliseconds 100 }
  }
  if ($null -eq $identity) {
    $identity = [pscustomobject]@{ Pid = $Process.Id; Image = $Process.ProcessName; StartTicks = $null; CommandLine = $null }
  }
  return [pscustomobject]@{
    Name        = $Name
    Pid         = [int]$identity.Pid
    Image       = $identity.Image
    StartTicks  = $identity.StartTicks
    CommandLine = $identity.CommandLine
  }
}

function Get-SessionRestartPlan {
  # Klasifikasi record sesi sebelumnya: Verified (masih proses yang sama),
  # Stale (PID sudah dipakai proses lain), Gone (sudah berhenti).
  $verified = @()
  $stale = @()
  $gone = @()
  foreach ($record in @(Get-SessionRecords)) {
    $identity = Get-ProcessIdentity -ProcessId $record.Pid
    if ($null -eq $identity) { $gone += $record; continue }
    if (Test-ProcessRecordMatches -Record $record -Identity $identity) {
      $verified += $record
    } else {
      $stale += $record
    }
  }
  return [pscustomobject]@{
    Verified = @($verified)
    Stale    = @($stale)
    Gone     = @($gone)
  }
}

function Get-PortOwnerProcessIds {
  param([int]$Port)
  # Pemilik port hanya untuk PELAPORAN; tidak pernah dipakai sebagai dasar
  # penghentian proses (kepemilikan harus terverifikasi lewat state sesi).
  try {
    $conns = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
  } catch {
    return @()
  }
  if ($null -eq $conns) { return @() }
  return @($conns | Select-Object -ExpandProperty OwningProcess -Unique)
}

function Get-PortAvailability {
  param([int]$Port)
  if (-not (Test-PortInUse -Port $Port)) {
    return [pscustomobject]@{ InUse = $false; OwnerPids = @(); OwnerNames = @() }
  }
  $ownerPids = @(Get-PortOwnerProcessIds -Port $Port)
  $ownerNames = @()
  foreach ($ownerPid in $ownerPids) {
    $identity = Get-ProcessIdentity -ProcessId $ownerPid
    if ($null -ne $identity) { $ownerNames += "$($identity.Image) (PID $ownerPid)" } else { $ownerNames += "PID $ownerPid" }
  }
  return [pscustomobject]@{ InUse = $true; OwnerPids = @($ownerPids); OwnerNames = @($ownerNames) }
}

function Stop-ProcessTree {
  param([int]$ProcessId)
  # Primitif penghentian (dipisah agar dapat diuji). /T = seluruh tree proses.
  try {
    & taskkill /PID $ProcessId /T /F 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
  } catch {
    return $false
  }
}

function Stop-VerifiedProcesses {
  param([object[]]$Records)
  # Hentikan HANYA proses yang terverifikasi masih milik RepoLens. Hasil:
  # daftar record yang TIDAK dapat dihentikan (masih hidup & terverifikasi).
  $remaining = @()
  foreach ($record in @($Records)) {
    if ($null -eq $record) { continue }
    $identity = Get-ProcessIdentity -ProcessId $record.Pid
    if ($null -eq $identity) { continue }
    if (-not (Test-ProcessRecordMatches -Record $record -Identity $identity)) {
      Write-WarnMsg "PID $($record.Pid) kini milik proses lain ('$($identity.Image)') — tidak dihentikan."
      continue
    }
    Write-Detail "Menghentikan $($record.Name) (PID $($record.Pid))..."
    if (Stop-ProcessTree -ProcessId $record.Pid) {
      Write-Detail "$($record.Name) (PID $($record.Pid)) dihentikan."
    } else {
      Write-FailMsg "Gagal menghentikan $($record.Name) (PID $($record.Pid))."
      $remaining += $record
    }
  }
  return @($remaining)
}

function Wait-ForStop {
  param([int[]]$ProcessIds, [int[]]$Ports, [int]$TimeoutSec)
  # Tunggu sampai seluruh proses target benar-benar berhenti DAN port yang
  # relevan bebas sebelum sesi baru dimulai.
  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ($true) {
    $alive = $false
    foreach ($processId in @($ProcessIds)) {
      if ($null -ne (Get-ProcessIdentity -ProcessId $processId)) { $alive = $true; break }
    }
    if (-not $alive) {
      $busy = $false
      foreach ($port in @($Ports)) {
        if (Test-PortInUse -Port $port) { $busy = $true; break }
      }
      if (-not $busy) { return $true }
    }
    if ((Get-Date) -ge $deadline) { return $false }
    Start-Sleep -Milliseconds 250
  }
}

function Stop-OwnProcesses {
  # Hanya menghentikan proses yang terverifikasi masih milik RepoLens (PID,
  # image, waktu mulai, dan command line cocok). Proses asing TIDAK disentuh.
  # Record yang gagal dihentikan tetap disimpan di state file agar dapat
  # dicoba lagi pada sesi berikutnya.
  $records = @(Get-SessionRecords)
  if ($records.Count -eq 0) {
    $script:Session = @()
    Save-SessionState
    return
  }
  $remaining = @(Stop-VerifiedProcesses -Records $records)
  $script:Session = @($remaining)
  Save-SessionState
}

function Invoke-NativeCommand {
  # Jalankan native command dengan stdout+stderr digabung TANPA memicu
  # NativeCommandError. Keberhasilan selalu ditentukan oleh ExitCode
  # ($LASTEXITCODE), bukan oleh adanya output di stderr.
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [string[]]$Arguments = @()
  )
  $previousPreference = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  try {
    $output = @(& $FilePath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $previousPreference
  }
  return [pscustomobject]@{
    ExitCode = $exitCode
    Output   = $output
  }
}

function Test-DockerDaemon {
  # Docker dianggap aktif hanya bila daemon menjawab dan Compose tersedia.
  $dockerCmd = Get-Command "docker" -ErrorAction SilentlyContinue
  if ($null -eq $dockerCmd) {
    Write-FailMsg "Docker CLI tidak ditemukan di PATH."
    Write-Detail "Pasang Docker Desktop, lalu jalankan ulang script."
    return $false
  }

  $info = Invoke-NativeCommand -FilePath "docker" `
    -Arguments @("info", "--format", "{{.ServerVersion}}")
  $versions = @($info.Output |
    Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) })
  if ($info.ExitCode -ne 0 -or $versions.Count -eq 0) {
    Write-FailMsg "Docker tidak aktif."
    Write-Detail "Jalankan Docker Desktop dan tunggu hingga siap, lalu ulangi."
    if ($info.Output.Count -gt 0) {
      Write-Detail ([string]($info.Output | Select-Object -Last 1))
    }
    return $false
  }

  $compose = Invoke-NativeCommand -FilePath "docker" -Arguments @("compose", "version")
  if ($compose.ExitCode -ne 0) {
    Write-FailMsg "Docker Compose tidak tersedia."
    Write-Detail "Pastikan plugin Docker Compose terpasang bersama Docker Desktop."
    if ($compose.Output.Count -gt 0) {
      Write-Detail ([string]($compose.Output | Select-Object -Last 1))
    }
    return $false
  }

  Write-Detail "Docker  : $([string]$versions[0])"
  return $true
}

function Get-ComposeArgs {
  return @(
    "compose",
    "-f", $script:ComposeFile,
    "--project-directory", $script:RepoRoot
  )
}

function Get-PostgresContainerId {
  $composeArgs = @(Get-ComposeArgs) + @("ps", "-a", "-q", "postgres")
  $result = Invoke-NativeCommand -FilePath "docker" -Arguments $composeArgs
  if ($result.ExitCode -ne 0) { return $null }
  return ($result.Output |
    ForEach-Object { [string]$_ } |
    Where-Object { $_ -match '^[0-9a-f]{12,64}$' } |
    Select-Object -First 1)
}

function Get-PostgresContainerState {
  param([string]$ContainerId)
  if ([string]::IsNullOrWhiteSpace($ContainerId)) { return "missing" }
  $result = Invoke-NativeCommand -FilePath "docker" `
    -Arguments @("inspect", "--format", "{{.State.Status}}", $ContainerId)
  if ($result.ExitCode -ne 0) { return "unknown" }
  $state = @($result.Output |
    ForEach-Object { [string]$_ } |
    Where-Object { $_ -match '^(created|running|paused|restarting|removing|exited|dead)$' } |
    Select-Object -First 1)
  if ($state.Count -eq 0) { return "unknown" }
  return [string]$state[0]
}

function Test-PostgresReady {
  $composeArgs = @(Get-ComposeArgs) + @(
    "exec", "-T", "postgres", "sh", "-c",
    'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
  )
  $result = Invoke-NativeCommand -FilePath "docker" -Arguments $composeArgs
  return ($result.ExitCode -eq 0)
}

function Ensure-RepoLensPostgres {
  param([int]$TimeoutSec)
  # Hanya menyentuh service PostgreSQL dari docker-compose.yml RepoLens.
  if (-not (Test-Path -LiteralPath $script:ComposeFile)) {
    Write-FailMsg "docker-compose.yml tidak ditemukan di $($script:ComposeFile)."
    return $false
  }

  $containerId = Get-PostgresContainerId
  $state = Get-PostgresContainerState -ContainerId $containerId

  if ($state -eq "running") {
    Write-Detail "Container PostgreSQL sudah berjalan."
  } else {
    if ($state -eq "missing") {
      Write-Detail "Container PostgreSQL belum ada; membuat dari docker-compose.yml."
    } else {
      Write-Detail "Container PostgreSQL berstatus '$state'; menjalankan container yang ada."
    }
    $composeArgs = @(Get-ComposeArgs) + @("up", "-d", "postgres")
    $result = Invoke-NativeCommand -FilePath "docker" -Arguments $composeArgs
    if ($result.ExitCode -ne 0) {
      Write-FailMsg "Gagal menjalankan container PostgreSQL RepoLens (exit code $($result.ExitCode))."
      foreach ($line in @($result.Output | Select-Object -Last 3)) {
        Write-Detail ([string]$line)
      }
      return $false
    }
  }

  $deadline = (Get-Date).AddSeconds($TimeoutSec)
  while ((Get-Date) -lt $deadline) {
    $containerId = Get-PostgresContainerId
    if (-not [string]::IsNullOrWhiteSpace($containerId)) {
      $state = Get-PostgresContainerState -ContainerId $containerId
      if ($state -eq "exited" -or $state -eq "dead") {
        Write-FailMsg "Container PostgreSQL RepoLens berhenti (state: $state)."
        Write-Detail "Periksa log: docker compose -f `"$($script:ComposeFile)`" logs postgres"
        return $false
      }
      if (Test-PostgresReady) {
        Write-Ok "PostgreSQL siap menerima koneksi."
        return $true
      }
    }
    Start-Sleep -Milliseconds 1000
  }

  Write-FailMsg "PostgreSQL belum siap menerima koneksi dalam $TimeoutSec detik."
  Write-Detail "Periksa status/log container:"
  Write-Detail "  docker compose -f `"$($script:ComposeFile)`" ps postgres"
  Write-Detail "  docker compose -f `"$($script:ComposeFile)`" logs postgres"
  return $false
}

# Path state sesi RepoLens (dipakai untuk safe restart).
$script:StateFilePath = Get-SessionStatePath

# Didukung dot-source (mis. oleh test) untuk memuat fungsi tanpa menjalankan
# seluruh script. Pemanggilan normal ($MyInvocation.InvocationName -ne ".") tetap
# menjalankan isi script.
if ($MyInvocation.InvocationName -eq ".") { return }

# Muat state sesi sebelumnya; verifikasi ulang dilakukan sebelum penghentian.
$script:Session = @(Read-SessionState)

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
    Write-WarnMsg "backend/.env belum ada — memakai URL database default (localhost, tanpa kredensial)."
    Write-Detail "Bila PostgreSQL lokal memakai kredensial (mis. Docker Compose), salin contoh:"
    Write-Detail "  Copy-Item backend\.env.example backend\.env"
    Write-Detail "Lalu jalankan migrasi sekali: cd backend; alembic upgrade head"
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

# ---------------- [CHECK] PostgreSQL (Docker Compose) ----------------
# Backend membutuhkan database yang siap sebelum menerima request. Periksa
# Docker dan service postgres milik RepoLens; hentikan startup dengan aman
# bila tidak dapat dipastikan siap. Container/layanan lain tidak disentuh.
if ($wantBackend) {
  Write-Check "PostgreSQL (Docker Compose)"
  if (-not (Test-DockerDaemon)) { exit 1 }
  if (-not (Ensure-RepoLensPostgres -TimeoutSec $PostgresReadyTimeoutSec)) {
    Write-Detail "Startup dihentikan sebelum backend/frontend dijalankan."
    exit 1
  }
}

# ---------------- Safe restart: hentikan sesi RepoLens sebelumnya ----------------
# Hanya proses yang TERVERIFIKASI milik RepoLens (lewat state sesi sebelumnya)
# yang dihentikan. Proses asing di port yang sama TIDAK pernah disentuh; bila
# identifikasi/penghentian tidak aman, script berhenti dengan FAIL.
Write-Check "Previous RepoLens session"
if (@(Get-SessionRecords).Count -eq 0) {
  Write-Detail "Tidak ada state sesi RepoLens sebelumnya."
  Write-Detail "  State: $($script:StateFilePath)"
  Write-Ok "Tidak ada proses RepoLens sesi sebelumnya yang perlu dihentikan."
} else {
  Write-Detail "State : $($script:StateFilePath)"
  $plan = Get-SessionRestartPlan
  foreach ($record in @($plan.Stale)) {
    Write-Detail "PID $($record.Pid) tidak lagi milik '$($record.Name)' (kemungkinan PID reuse) — dilewati."
  }
  foreach ($record in @($plan.Gone)) {
    Write-Detail "$($record.Name) (PID $($record.Pid)) sudah berhenti — dilewati."
  }

  if (@($plan.Verified).Count -eq 0) {
    $script:Session = @()
    Save-SessionState
    Write-Ok "Tidak ada proses RepoLens sesi sebelumnya yang masih aktif."
  } else {
    Write-Wait "Menghentikan $(@($plan.Verified).Count) proses RepoLens sesi sebelumnya"
    $failed = @(Stop-VerifiedProcesses -Records @($plan.Verified))
    if ($failed.Count -gt 0) {
      # Proses terverifikasi milik RepoLens tetapi tidak dapat dihentikan:
      # berhenti dengan FAIL, jangan menyentuh proses asing, dan simpan state
      # agar dapat dicoba lagi pada sesi berikutnya.
      $script:Session = @($failed)
      Save-SessionState
      Write-FailMsg "Proses RepoLens sesi sebelumnya tidak dapat dihentikan dengan aman."
      foreach ($record in $failed) {
        Write-Detail "$($record.Name) (PID $($record.Pid)) masih berjalan — hentikan manual lalu ulangi."
      }
      Write-Detail "Tidak ada proses lain yang disentuh."
      exit 1
    }

    $restartPorts = @($FrontendPort, $BackendPort)
    $cleared = Wait-ForStop -ProcessIds @($plan.Verified | ForEach-Object { [int]$_.Pid }) -Ports $restartPorts -TimeoutSec $StopTimeoutSec
    if (-not $cleared) {
      Write-FailMsg "Proses RepoLens sesi sebelumnya belum berhenti / port belum bebas dalam ${StopTimeoutSec} detik."
      $stillAlive = @($plan.Verified | Where-Object { $null -ne (Get-ProcessIdentity -ProcessId $_.Pid) })
      if ($stillAlive.Count -gt 0) {
        $stillAliveText = (@($stillAlive | ForEach-Object { "$($_.Name) (PID $($_.Pid))" }) -join ", ")
        Write-Detail "Masih berjalan: $stillAliveText."
      } else {
        Write-Detail "Semua proses RepoLens sesi sebelumnya sudah berhenti; port kemungkinan dipakai proses lain."
      }
      Write-Detail "Tidak ada proses lain yang disentuh. Periksa manual lalu ulangi."
      exit 1
    }
    $script:Session = @()
    Save-SessionState
    Write-Ok "Sesi sebelumnya dihentikan; proses berhenti dan port tersedia."
  }
}

# ---------------- Cek port (tidak mematikan proses lain) ----------------
Write-Check "Port availability"
$portBlocked = $false
if ($wantFrontend) {
  $frontendAvailability = Get-PortAvailability -Port $FrontendPort
  if ($frontendAvailability.InUse) {
    $portBlocked = $true
    Write-FailMsg "Port $FrontendPort sudah digunakan proses lain."
    if (@($frontendAvailability.OwnerNames).Count -gt 0) {
      Write-Detail "Pemilik port: $(@($frontendAvailability.OwnerNames) -join ', ') (tidak terverifikasi milik RepoLens)."
    }
    Write-Detail "Proses pemilik port tidak dihentikan. Ulangi dengan port lain, mis. -FrontendPort 5174."
  }
}
if ($wantBackend) {
  $backendAvailability = Get-PortAvailability -Port $BackendPort
  if ($backendAvailability.InUse) {
    $portBlocked = $true
    Write-FailMsg "Port $BackendPort sudah digunakan proses lain."
    if (@($backendAvailability.OwnerNames).Count -gt 0) {
      Write-Detail "Pemilik port: $(@($backendAvailability.OwnerNames) -join ', ') (tidak terverifikasi milik RepoLens)."
    }
    Write-Detail "Proses pemilik port tidak dihentikan. Ulangi dengan port lain, mis. -BackendPort 8001."
  }
}
if ($portBlocked) { exit 1 }
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
    $script:Session += New-SessionRecord -Name "frontend (vite)" -Process $frontendProcess
    Save-SessionState
    Write-Detail "PID $($frontendProcess.Id) -> $FrontendUrl"
  }

  if ($wantBackend) {
    Write-Start "Backend (Uvicorn) di $BackendDir"
    $backendProcess = Start-Process -FilePath $backendPython `
      -ArgumentList "-m", "uvicorn", "app.main:app", "--reload", "--port", "$BackendPort" `
      -WorkingDirectory $BackendDir -NoNewWindow -PassThru
    $script:Session += New-SessionRecord -Name "backend (uvicorn)" -Process $backendProcess
    Save-SessionState
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
      foreach ($child in @(Get-SessionRecords)) {
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
