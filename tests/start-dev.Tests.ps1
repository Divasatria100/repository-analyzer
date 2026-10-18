<#
.SYNOPSIS
  Pengujian untuk start-dev.ps1 — fokus pada SAFE RESTART.

.DESCRIPTION
  Menguji perilaku safe restart tanpa menjalankan layanan:
    - Menghentikan HANYA proses RepoLens sesi sebelumnya yang terverifikasi
      (PID + image + waktu mulai + command line); PID reuse tidak dihentikan.
    - Port yang dipakai proses asing dilaporkan sebagai error dan TIDAK disentuh.
    - Kegagalan cleanup (proses tidak dapat dihentikan) menyimpan state agar
      dapat dicoba lagi, tanpa menyentuh proses asing.

  Script dimuat dengan dot-source (didukung start-dev.ps1) sehingga fungsi
  dapat diuji langsung; body utama (menjalankan server) tidak dieksekusi.

  Jalankan:  Invoke-Pester .\tests\start-dev.Tests.ps1
#>

$here = $PSScriptRoot
$scriptPath = Join-Path (Split-Path -Parent $here) "start-dev.ps1"

# $ErrorActionPreference script di-set "Stop"; simpan & kembalikan agar tidak
# memengaruhi harness Pester.
$savedErrorActionPreference = $ErrorActionPreference
. $scriptPath
$ErrorActionPreference = $savedErrorActionPreference

# Lokasi state default untuk test (tetap di temp; path repo asli tidak disentuh).
$script:DefaultTestStatePath = Join-Path ([System.IO.Path]::GetTempPath()) ("repolens-dev-tests-" + [guid]::NewGuid().ToString("N") + ".json")
$script:StateFilePath = $script:DefaultTestStatePath

$script:BackendCommandLine = "python -m uvicorn app.main:app --reload --port 8000"
$script:FrontendCommandLine = "cmd /c npm run dev -- --port 5173 --strictPort"

function New-TestRecord {
  param(
    [string]$Name = "backend (uvicorn)",
    [int]$ProcessId = 4321,
    [string]$Image = "python.exe",
    [long]$StartTicks = 111,
    [string]$CommandLine = $script:BackendCommandLine
  )
  return [pscustomobject]@{
    Name        = $Name
    Pid         = $ProcessId
    Image       = $Image
    StartTicks  = $StartTicks
    CommandLine = $CommandLine
  }
}

function New-TestIdentity {
  param(
    [int]$ProcessId = 4321,
    [string]$Image = "python.exe",
    [long]$StartTicks = 111,
    [string]$CommandLine = $script:BackendCommandLine
  )
  return [pscustomobject]@{
    Pid         = $ProcessId
    Image       = $Image
    StartTicks  = $StartTicks
    CommandLine = $CommandLine
  }
}

Describe "start-dev.ps1: dapat dimuat untuk pengujian (dot-source)" {
  It "mendefinisikan fungsi safe restart tanpa menjalankan body utama" {
    ([bool](Get-Command Get-SessionRestartPlan -ErrorAction SilentlyContinue)) | Should Be $true
    ([bool](Get-Command Stop-VerifiedProcesses -ErrorAction SilentlyContinue)) | Should Be $true
    ([bool](Get-Command Get-PortAvailability -ErrorAction SilentlyContinue)) | Should Be $true
  }

  It "menghormati override lokasi state (REPOLENS_DEV_STATE_FILE)" {
    $saved = $env:REPOLENS_DEV_STATE_FILE
    try {
      $custom = Join-Path ([System.IO.Path]::GetTempPath()) "repolens-dev-custom-state.json"
      $env:REPOLENS_DEV_STATE_FILE = $custom
      Get-SessionStatePath | Should Be $custom
    } finally {
      $env:REPOLENS_DEV_STATE_FILE = $saved
    }
  }
}

Describe "verifikasi identitas proses (pengaman PID reuse)" {
  It "menerima proses yang identitasnya persis sama" {
    $record = New-TestRecord
    $identity = New-TestIdentity
    (Test-ProcessRecordMatches -Record $record -Identity $identity) | Should Be $true
  }

  It "menolak PID reuse: waktu mulai berbeda" {
    $record = New-TestRecord -StartTicks 111
    $identity = New-TestIdentity -StartTicks 999
    (Test-ProcessRecordMatches -Record $record -Identity $identity) | Should Be $false
  }

  It "menolak PID reuse: image berbeda" {
    $record = New-TestRecord -Image "python.exe"
    $identity = New-TestIdentity -Image "chrome.exe"
    (Test-ProcessRecordMatches -Record $record -Identity $identity) | Should Be $false
  }

  It "menolak PID reuse: command line berbeda" {
    $record = New-TestRecord -CommandLine $script:BackendCommandLine
    $identity = New-TestIdentity -CommandLine "notepad.exe"
    (Test-ProcessRecordMatches -Record $record -Identity $identity) | Should Be $false
  }

  It "menolak bila waktu mulai tidak dapat dibaca (fail-safe)" {
    $record = New-TestRecord -StartTicks 111
    $identity = New-TestIdentity
    $identity.StartTicks = $null
    (Test-ProcessRecordMatches -Record $record -Identity $identity) | Should Be $false
  }

  It "menolak bila identitas proses tidak ada" {
    (Test-ProcessRecordMatches -Record (New-TestRecord) -Identity $null) | Should Be $false
  }
}

Describe "safe restart: hentikan hanya proses RepoLens sesi sebelumnya" {
  BeforeEach {
    $script:StateFilePath = Join-Path $TestDrive "session.json"
    $script:Session = @()
  }

  It "menghentikan proses RepoLens yang terverifikasi" {
    $record = New-TestRecord -ProcessId 4321
    $script:Session = @($record)
    Mock Get-ProcessIdentity { param($ProcessId) return (New-TestIdentity -ProcessId $ProcessId) }
    Mock Stop-ProcessTree { param($ProcessId) return $true }

    $plan = Get-SessionRestartPlan
    @($plan.Verified).Count | Should Be 1
    @($plan.Stale).Count | Should Be 0
    @($plan.Gone).Count | Should Be 0

    $remaining = @(Stop-VerifiedProcesses -Records @($plan.Verified))
    $remaining.Count | Should Be 0
    Assert-MockCalled Stop-ProcessTree -Times 1 -Exactly -ParameterFilter { $ProcessId -eq 4321 }
  }

  It "mengabaikan record yang prosesnya sudah berhenti" {
    $record = New-TestRecord -ProcessId 4400
    $script:Session = @($record)
    Mock Get-ProcessIdentity { param($ProcessId) return $null }
    Mock Stop-ProcessTree { param($ProcessId) return $true }

    $plan = Get-SessionRestartPlan
    @($plan.Gone).Count | Should Be 1
    @($plan.Verified).Count | Should Be 0
    Assert-MockCalled Stop-ProcessTree -Times 0 -Exactly -ParameterFilter { $ProcessId -eq 4400 }
  }

  It "TIDAK menghentikan proses ketika PID sudah dipakai proses lain (PID reuse)" {
    $record = New-TestRecord -Name "backend (uvicorn)" -ProcessId 6000 -Image "python.exe" -StartTicks 1
    $script:Session = @($record)
    # PID 6000 sekarang milik proses lain (image & waktu mulai berbeda).
    Mock Get-ProcessIdentity { param($ProcessId) return (New-TestIdentity -ProcessId 6000 -Image "chrome.exe" -StartTicks 777 -CommandLine "chrome.exe") }
    Mock Stop-ProcessTree { param($ProcessId) return $true }

    $plan = Get-SessionRestartPlan
    @($plan.Verified).Count | Should Be 0
    @($plan.Stale).Count | Should Be 1

    $remaining = @(Stop-VerifiedProcesses -Records @($plan.Stale))
    $remaining.Count | Should Be 0
    Assert-MockCalled Stop-ProcessTree -Times 0 -Exactly -ParameterFilter { $ProcessId -eq 6000 }
  }
}

Describe "port yang digunakan proses asing tidak disentuh" {
  It "melaporkan port terpakai beserta pemiliknya, tanpa menghentikan proses" {
    Mock Test-PortInUse { param($Port) return $true }
    Mock Get-PortOwnerProcessIds { param($Port) return @(9999) }
    Mock Get-ProcessIdentity { param($ProcessId) return (New-TestIdentity -ProcessId 9999 -Image "nginx.exe" -StartTicks 42 -CommandLine "nginx.exe") }
    Mock Stop-ProcessTree { param($ProcessId) return $true }

    $availability = Get-PortAvailability -Port 8000
    $availability.InUse | Should Be $true
    $availability.OwnerPids.Count | Should Be 1
    $availability.OwnerPids[0] | Should Be 9999
    (@($availability.OwnerNames) -join ",") | Should Match "nginx.exe"
    Assert-MockCalled Stop-ProcessTree -Times 0 -Exactly -ParameterFilter { $ProcessId -eq 9999 }
  }

  It "melaporkan port bebas tanpa menyentuh proses apa pun" {
    Mock Test-PortInUse { param($Port) return $false }
    Mock Get-PortOwnerProcessIds { param($Port) return @() }
    Mock Stop-ProcessTree { param($ProcessId) return $true }

    $availability = Get-PortAvailability -Port 5199
    $availability.InUse | Should Be $false
    $availability.OwnerPids.Count | Should Be 0
    Assert-MockCalled Get-PortOwnerProcessIds -Times 0 -Exactly -ParameterFilter { $Port -eq 5199 }
    Assert-MockCalled Stop-ProcessTree -Times 0 -Exactly -ParameterFilter { $ProcessId -eq 5199 }
  }
}

Describe "menunggu proses berhenti dan port bebas" {
  It "kembali true saat proses sudah berhenti dan port bebas" {
    Mock Get-ProcessIdentity { param($ProcessId) return $null }
    Mock Test-PortInUse { param($Port) return $false }
    (Wait-ForStop -ProcessIds @(4321) -Ports @(8000) -TimeoutSec 2) | Should Be $true
  }

  It "kembali false saat proses tidak juga berhenti (timeout)" {
    Mock Get-ProcessIdentity { param($ProcessId) return (New-TestIdentity -ProcessId $ProcessId) }
    Mock Test-PortInUse { param($Port) return $false }
    (Wait-ForStop -ProcessIds @(4321) -Ports @(8000) -TimeoutSec 1) | Should Be $false
  }

  It "kembali false saat port masih dipakai meski proses sudah berhenti" {
    Mock Get-ProcessIdentity { param($ProcessId) return $null }
    Mock Test-PortInUse { param($Port) return $true }
    (Wait-ForStop -ProcessIds @(4321) -Ports @(8000) -TimeoutSec 1) | Should Be $false
  }
}

Describe "kegagalan cleanup" {
  BeforeEach {
    $script:StateFilePath = Join-Path $TestDrive "session.json"
    $script:Session = @()
  }

  It "menyimpan record yang gagal dihentikan agar dapat dicoba lagi" {
    $record = New-TestRecord -Name "frontend (vite)" -ProcessId 5555 -Image "cmd.exe" -StartTicks 222 -CommandLine $script:FrontendCommandLine
    $script:Session = @($record)
    Mock Get-ProcessIdentity { param($ProcessId) return (New-TestIdentity -ProcessId 5555 -Image "cmd.exe" -StartTicks 222 -CommandLine $script:FrontendCommandLine) }
    Mock Stop-ProcessTree { param($ProcessId) return $false }

    Stop-OwnProcesses

    Assert-MockCalled Stop-ProcessTree -Times 1 -Exactly -ParameterFilter { $ProcessId -eq 5555 }
    (Test-Path -LiteralPath $script:StateFilePath) | Should Be $true
    $persisted = @(Read-SessionState)
    $persisted.Count | Should Be 1
    $persisted[0].Pid | Should Be 5555
    @(Get-SessionRecords).Count | Should Be 1
  }

  It "membersihkan state setelah semua proses terverifikasi berhasil dihentikan" {
    $record = New-TestRecord -ProcessId 4444
    $script:Session = @($record)
    Mock Get-ProcessIdentity { param($ProcessId) return (New-TestIdentity -ProcessId $ProcessId) }
    Mock Stop-ProcessTree { param($ProcessId) return $true }

    Save-SessionState
    (Test-Path -LiteralPath $script:StateFilePath) | Should Be $true

    Stop-OwnProcesses

    (Test-Path -LiteralPath $script:StateFilePath) | Should Be $false
    @(Get-SessionRecords).Count | Should Be 0
  }

  It "mempertahankan state file bila proses gagal dihentikan" {
    $record = New-TestRecord -ProcessId 3333
    $script:Session = @($record)
    Mock Get-ProcessIdentity { param($ProcessId) return (New-TestIdentity -ProcessId $ProcessId) }
    Mock Stop-ProcessTree { param($ProcessId) return $false }

    Stop-OwnProcesses
    Stop-OwnProcesses

    (Test-Path -LiteralPath $script:StateFilePath) | Should Be $true
    @(Get-SessionRecords).Count | Should Be 1
    Assert-MockCalled Stop-ProcessTree -Times 2 -Exactly -ParameterFilter { $ProcessId -eq 3333 }
  }
}

Describe "state sesi (persistensi)" {
  BeforeEach {
    $script:StateFilePath = Join-Path $TestDrive "session.json"
    $script:Session = @()
  }

  It "menyimpan dan memuat kembali beberapa record" {
    $script:Session = @(
      (New-TestRecord -Name "frontend (vite)" -ProcessId 111 -Image "cmd.exe" -StartTicks 10 -CommandLine $script:FrontendCommandLine),
      (New-TestRecord -Name "backend (uvicorn)" -ProcessId 222 -Image "python.exe" -StartTicks 20)
    )
    Save-SessionState

    $loaded = @(Read-SessionState)
    $loaded.Count | Should Be 2
    $loaded[0].Pid | Should Be 111
    $loaded[0].Image | Should Be "cmd.exe"
    $loaded[1].Pid | Should Be 222
    $loaded[1].StartTicks | Should Be 20
    $loaded[1].CommandLine | Should Be $script:BackendCommandLine
  }

  It "menyimpan dan memuat kembali satu record" {
    $script:Session = @(New-TestRecord -ProcessId 777 -StartTicks 33)
    Save-SessionState

    $loaded = @(Read-SessionState)
    $loaded.Count | Should Be 1
    $loaded[0].Pid | Should Be 777
    $loaded[0].StartTicks | Should Be 33
  }

  It "menghapus state file bila tidak ada record tersisa" {
    $script:Session = @(New-TestRecord)
    Save-SessionState
    (Test-Path -LiteralPath $script:StateFilePath) | Should Be $true

    $script:Session = @()
    Save-SessionState
    (Test-Path -LiteralPath $script:StateFilePath) | Should Be $false
  }

  It "mengembalikan daftar kosong bila state file tidak ada" {
    @(Read-SessionState).Count | Should Be 0
  }
}

Describe "integrasi proses nyata: identifikasi + penghentian aman" {
  It "mengenali, memverifikasi, dan menghentikan proses yang direkam" {
    $process = Start-Process -FilePath "powershell.exe" `
      -ArgumentList "-NoProfile", "-Command", "Start-Sleep -Seconds 120" `
      -PassThru -WindowStyle Hidden
    try {
      $record = New-SessionRecord -Name "uji proses anak" -Process $process
      $record.Pid | Should Be $process.Id
      ([string]::IsNullOrWhiteSpace($record.Image)) | Should Be $false
      ($null -ne $record.StartTicks) | Should Be $true

      $identity = Get-ProcessIdentity -ProcessId $record.Pid
      ($null -ne $identity) | Should Be $true
      (Test-ProcessRecordMatches -Record $record -Identity $identity) | Should Be $true

      $remaining = @(Stop-VerifiedProcesses -Records @($record))
      $remaining.Count | Should Be 0
      (Get-ProcessIdentity -ProcessId $record.Pid) | Should Be $null
    } finally {
      if ($null -ne (Get-ProcessIdentity -ProcessId $process.Id)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
      }
    }
  }

  It "tidak menghentikan proses lain ketika identitas tidak cocok" {
    $process = Start-Process -FilePath "powershell.exe" `
      -ArgumentList "-NoProfile", "-Command", "Start-Sleep -Seconds 120" `
      -PassThru -WindowStyle Hidden
    try {
      # Record dengan waktu mulai yang salah -> tidak terverifikasi.
      $bogus = [pscustomobject]@{
        Name        = "backend (uvicorn)"
        Pid         = $process.Id
        Image       = "python.exe"
        StartTicks  = 1
        CommandLine = $script:BackendCommandLine
      }
      $remaining = @(Stop-VerifiedProcesses -Records @($bogus))
      $remaining.Count | Should Be 0
      # Proses tetap hidup karena tidak terverifikasi milik RepoLens.
      ($null -ne (Get-ProcessIdentity -ProcessId $process.Id)) | Should Be $true
    } finally {
      if ($null -ne (Get-ProcessIdentity -ProcessId $process.Id)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
      }
    }
  }
}
