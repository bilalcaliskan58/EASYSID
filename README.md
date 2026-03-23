# EASYSID - Windows SID Changing Utility

[![Build](https://github.com/bilalcaliskan58/EASYSID/actions/workflows/release.yml/badge.svg)](https://github.com/bilalcaliskan58/EASYSID/actions/workflows/release.yml)

Windows makinelerde Security Identifier (SID) degistirme araci. Sysprep alternatifi olarak imajlama, klonlama ve makine kimlik yenileme senaryolari icin tasarlanmistir.

## Indirme

[Releases](https://github.com/bilalcaliskan58/EASYSID/releases/latest) sayfasindan `EASYSID.exe` dosyasini indirin. Kurulum gerektirmez, tek dosya, self-contained.

## Ozellikler

- **SID Degistirme**: Makine SID'ini rastgele veya belirtilen degerle degistirir
- **Bilgisayar Adi Degistirme**: Yeni isim, mevcut isim veya rastgele (PC-XXXXXX)
- **Makine Kimlik Yenileme**: MachineGuid, MachineId, WSUS ID, MSDTC CID, Device ID, DHCPv6 DUID
- **Ikon Cache Temizleme**: SID degisikligi sonrasi ikon bozulmalari onlenir
- **Kapsamli Backup/Restore**: SHA256 butunluk dogrulamali snapshot sistemi
- **WinPE Offline Restore**: Offline Windows kurulumuna snapshot geri yukleme
- **Active Directory Uyarisi**: Domain uyeligi algilanir ve islem engellenir
- **BitLocker Algilama**: BitLocker aktifse islem engellenir
- **Interaktif Mod**: Argumsiz calistirildiginda adim adim sihirbaz
- **Iptal Mekanizmasi**: /CANCEL ile bekleyen islemleri temizle

## Gereksinimler

- Windows 10/11 (x64)
- Administrator yetkisi

## Kullanim

### Interaktif Mod (Argumsiz)
```
EASYSID.exe
```
Adim adim sorar: bilgisayar adi, SID, shutdown/reboot/cancel.

### Komut Satiri

```bash
# SID degistir, onay sor, yeniden baslat
EASYSID /F /R

# SID degistir + bilgisayar adi degistir
EASYSID /COMPNAME=MYPC /F /R

# Belirli SID ata
EASYSID /SID=S-1-5-21-1-2-3 /F /R

# Sadece bilgisayar adi degistir (SID'e dokunma)
EASYSID /COMPNAME=NEWNAME /NS /F /R

# Imajlama icin kapat (Phase 2 sonraki boot'ta calisir)
EASYSID /F /S

# Bekleyen islemi iptal et
EASYSID /CANCEL

# Snapshot listele
EASYSID /LIST

# Geri yukle
EASYSID /ROLLBACK=C:\ProgramData\EASYSID\Backups\20260323_143000

# WinPE'den offline geri yukleme
EASYSID /ROLLBACK=D:\ProgramData\EASYSID\Backups\20260323_143000 /OFFLINE=D:
```

### Tum Parametreler

| Parametre | Aciklama |
|-----------|----------|
| `/F` | Onay sorma (force) |
| `/R` | Islem sonrasi yeniden baslat |
| `/S` | Islem sonrasi kapat |
| `/NS` | Sadece bilgisayar adi degistir, SID'e dokunma |
| `/COMPNAME=<isim>` | Yeni bilgisayar adi (`?`=rastgele PC-XXXXXX) |
| `/COMPDESCR=<aciklama>` | Bilgisayar aciklamasi |
| `/SID=<sid>` | Belirli SID ata (varsayilan: rastgele) |
| `/OS=<yol>` | Offline Windows kurulumu hedefi |
| `/NW` | WSUS ID sifirlamayi atla |
| `/NCID` | MSDTC CID sifirlamayi atla |
| `/NDI` | Device ID sifirlamayi atla |
| `/NMG` | MachineGuid sifirlamayi atla |
| `/NMID` | Machine ID sifirlamayi atla |
| `/NDUID` | DHCPv6 DUID sifirlamayi atla |
| `/NOBACKUP` | Otomatik snapshot olusturmayi atla |
| `/BACKUPDIR=<yol>` | Ozel snapshot dizini |
| `/ROLLBACK=<yol>` | Snapshot'tan geri yukle |
| `/OFFLINE=<surucu>` | WinPE offline restore hedefi (`/ROLLBACK` ile kullanilir) |
| `/LIST` | Mevcut snapshot'lari listele |
| `/CANCEL` | Bekleyen SID degisikligini iptal et |
| `/CLEARNOTICE` | WinLogon mesajlarini temizle |

## Calisma Prensibi

EASYSID iki fazli calisir:

### Faz 1 - Hazirlama (Kullanici Oturumu)
1. BitLocker ve domain uyeligi kontrol edilir
2. Mevcut SID okunur, yeni SID belirlenir
3. Exe `C:\Windows\Temp`'e kopyalanir (flash/ag destegi)
4. UCPD driver devre disi birakilir
5. Scheduled task olusturulur (XML, pilde de calisir)
6. WinLogon login ekrani mesaji ayarlanir
7. Makine kapatilir veya yeniden baslatilir

### Faz 2 - Uygulama (SYSTEM, Boot Sonrasi)
1. **Backup**: Registry hive'lari, profil hive'lari, DPAPI key'leri, tarayici profilleri
2. **SID Degisikligi**:
   - SAM hive binary patch (dinamik offset bulma)
   - SAM group membership patch (Administrators, Users vb.)
   - SECURITY hive (LsaSetInformationPolicy)
   - ProfileList remapping (orphan profil temizleme dahil)
   - Registry key security descriptor patching (tum hive'lar + kullanici hive'lari)
   - LSA account rights migrasyonu
   - Registry SID string replacement (SOFTWARE, SYSTEM)
   - Service logon SID guncelleme
   - Scheduled Task XML SID guncelleme (encoding-safe)
3. **Profil Migrasyonu**: DPAPI key klasoru tasima, Chromium machine ID temizleme, dosya ACL'leri
4. **Kimlik Sifirlama**: MachineGuid, MachineId, WSUS, MSDTC, DeviceId, DHCP DUID
5. **Temizlik**: Ikon cache, shell bag, TrayNotify, AppxAllUserStore
6. **Yeniden Baslatma**: 4 katmanli fallback (shutdown.exe -> InitiateSystemShutdownEx -> ExitWindowsEx -> NtShutdownSystem)

## Backup / Restore

### Snapshot Icerigi
```
C:\ProgramData\EASYSID\Backups\20260323_143000\
  metadata.txt              # Tarih, SID, makine, OS versiyonu
  identity.txt              # MachineGuid, MachineId, SusClientId
  manifest.sha256           # SHA256 butunluk dogrulama
  Registry/                 # .reg export dosyalari (online import)
  Hives/                    # SAM.hiv, SECURITY.hiv, SOFTWARE.hiv, SYSTEM.hiv
  Profiles/
    <kullanici>/
      NTUSER.DAT
      UsrClass.dat
      DPAPI/                # DPAPI master key'leri
      Browsers/
        Chrome/             # Local State, Preferences, Bookmarks
        Edge/
```

### Restore Yontemleri

| Yontem | Komut | Aciklama |
|--------|-------|----------|
| **Online** | `EASYSID /ROLLBACK=<yol>` | Boot-time SYSTEM task ile tam restore |
| **Offline** | `EASYSID /ROLLBACK=<yol> /OFFLINE=D:` | WinPE'den tam hive restore |
| **Listeleme** | `EASYSID /LIST` | Snapshot listesi (tarih, makine, SID, boyut) |

Otomatik temizlik: En son 5 snapshot tutulur, eskileri silinir.

## Bilinen Sinirlamalar

| Sinir | Aciklama | Cozum |
|-------|----------|-------|
| **Varsayilan uygulamalar** | UserChoice hash'leri SID'e bagli, Windows hash algoritmasi gizli | SID degisikligi sonrasi Ayarlar > Varsayilan Uygulamalar'dan tekrar ayarla |
| **Chrome/Edge profilleri** | DPAPI sifreleme SID'e bagli, kaydedilmis parolalar kaybolur | Chrome Sync'i SID degisikliginden once etkinlestir |
| **Active Directory** | Domain trust iliskisi kirilir | Onceden domain'den cik, sonra tekrar katil |
| **BitLocker** | TPM registry degisikligini kurcalama olarak algilar | BitLocker'i SID degisikliginden once kapat |

## Proje Mimarisi (N-Tier)

```
EASYSID/
├── Program.cs                          # Entry point
├── EasySidApp.cs                       # Ana orkestrator
├── Models/
│   ├── Options.cs                      # Komut satiri secenekleri
│   └── ExitCode.cs                     # Cikis kodlari
├── Core/
│   └── SidOperations.cs                # SID olusturma, parse, binary patch
├── Infrastructure/
│   ├── NativeImports.cs                # P/Invoke tanimlari
│   ├── NativeStructs.cs                # P/Invoke struct'lari
│   ├── RegistryHelper.cs               # Registry erisim yardimcilari
│   └── ProcessRunner.cs                # Process calistirma
└── Services/
    ├── SidChangeService.cs             # Ana SID degisikligi
    ├── SidReadService.cs               # SID okuma (LSA/SAM/WMI)
    ├── ProfileMigrationService.cs      # Profil, DPAPI, ACL
    ├── SecurityDescriptorService.cs    # Registry SD patching
    ├── BackupService.cs                # Snapshot/rollback
    ├── IdentityResetService.cs         # Kimlik sifirlama
    ├── ComputerNameService.cs          # Bilgisayar adi
    ├── BackgroundTaskService.cs        # Scheduled task yonetimi
    ├── SystemProtectionService.cs      # UCPD driver, Defender
    ├── WinLogonService.cs              # Login notice, AutoLogon
    ├── ShutdownService.cs              # 4 katmanli reboot fallback
    ├── ChromiumService.cs              # Tarayici profil temizleme
    ├── CacheCleanupService.cs          # Ikon/shell cache temizleme
    ├── LsaAccountService.cs            # LSA account rights
    ├── ServiceLogonService.cs          # Servis SID guncelleme
    ├── HiveManagementService.cs        # Hive yukle/bosalt
    └── AppxCleanupService.cs           # Appx store temizleme
```

## Derleme

```bash
# Gelistirme
dotnet build -c Release

# Self-contained tek dosya
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=true -o ./publish
```

Her commit'te GitHub Actions otomatik olarak derler ve [Releases](https://github.com/bilalcaliskan58/EASYSID/releases) sayfasina yukler.

## Cikis Kodlari

| Kod | Anlam |
|-----|-------|
| 0 | Basarili |
| 1 | Gecersiz argumanlar / BitLocker aktif |
| 2 | Administrator yetkisi gerekli |
| 3 | Gerekli privilege eksik |
| 4 | SID degistirme basarisiz |
| 5 | Baska bir instance zaten calisiyor |
| 6 | Gecersiz Windows dizini |
| 10 | Yeniden baslatma gerekli |
| 11 | Registry hatasi |

## Log Dosyalari

- **Faz 2 log**: `C:\Windows\Temp\EASYSID_EASYSID.log`
- **Snapshot dizini**: `C:\ProgramData\EASYSID\Backups\`

## Lisans

Bu yazilim ozel bir lisans altinda dagitilmaktadir.

---

# EASYSID - Windows SID Changing Utility (English)

[![Build](https://github.com/bilalcaliskan58/EASYSID/actions/workflows/release.yml/badge.svg)](https://github.com/bilalcaliskan58/EASYSID/actions/workflows/release.yml)

A Windows Security Identifier (SID) changing tool. Designed as a Sysprep alternative for imaging, cloning, and machine identity renewal scenarios.

## Download

Download `EASYSID.exe` from the [Releases](https://github.com/bilalcaliskan58/EASYSID/releases/latest) page. No installation required, single file, self-contained.

## Features

- **SID Change**: Changes the machine SID to a random or specified value
- **Computer Name Change**: New name, current name or random (PC-XXXXXX)
- **Machine Identity Renewal**: MachineGuid, MachineId, WSUS ID, MSDTC CID, Device ID, DHCPv6 DUID
- **Icon Cache Cleanup**: Prevents icon corruption after SID change
- **Comprehensive Backup/Restore**: SHA256 integrity verified snapshot system
- **WinPE Offline Restore**: Restore snapshots to offline Windows installations
- **Active Directory Detection**: Domain membership detected, operation blocked
- **BitLocker Detection**: Operation blocked if BitLocker is active
- **Interactive Mode**: Step-by-step wizard when run without arguments
- **Cancel Mechanism**: Clean up pending operations with /CANCEL

## Requirements

- Windows 10/11 (x64)
- Administrator privileges

## Usage

### Interactive Mode (No Arguments)
```
EASYSID.exe
```
Asks step by step: computer name, SID, shutdown/reboot/cancel.

### Command Line

```bash
# Change SID, force, reboot
EASYSID /F /R

# Change SID + computer name
EASYSID /COMPNAME=MYPC /F /R

# Assign specific SID
EASYSID /SID=S-1-5-21-1-2-3 /F /R

# Change only computer name (don't touch SID)
EASYSID /COMPNAME=NEWNAME /NS /F /R

# Shutdown for imaging (Phase 2 runs at next boot)
EASYSID /F /S

# Cancel pending operation
EASYSID /CANCEL

# List snapshots
EASYSID /LIST

# Restore from snapshot
EASYSID /ROLLBACK=C:\ProgramData\EASYSID\Backups\20260323_143000

# WinPE offline restore
EASYSID /ROLLBACK=D:\ProgramData\EASYSID\Backups\20260323_143000 /OFFLINE=D:
```

### All Parameters

| Parameter | Description |
|-----------|-------------|
| `/F` | Skip confirmation (force) |
| `/R` | Reboot after operation |
| `/S` | Shutdown after operation |
| `/NS` | Change only computer name, don't touch SID |
| `/COMPNAME=<name>` | New computer name (`?`=random PC-XXXXXX) |
| `/COMPDESCR=<desc>` | Computer description |
| `/SID=<sid>` | Assign specific SID (default: random) |
| `/OS=<path>` | Offline Windows installation target |
| `/NW` | Skip WSUS ID reset |
| `/NCID` | Skip MSDTC CID reset |
| `/NDI` | Skip Device ID reset |
| `/NMG` | Skip MachineGuid reset |
| `/NMID` | Skip Machine ID reset |
| `/NDUID` | Skip DHCPv6 DUID reset |
| `/NOBACKUP` | Skip automatic snapshot creation |
| `/BACKUPDIR=<path>` | Custom snapshot directory |
| `/ROLLBACK=<path>` | Restore from snapshot |
| `/OFFLINE=<drive>` | WinPE offline restore target (use with /ROLLBACK) |
| `/LIST` | List available snapshots |
| `/CANCEL` | Cancel pending SID change |
| `/CLEARNOTICE` | Clear WinLogon messages |

## How It Works

EASYSID operates in two phases:

### Phase 1 - Preparation (User Session)
1. BitLocker and domain membership checks
2. Current SID read, new SID determined
3. Exe copied to `C:\Windows\Temp` (flash/network support)
4. UCPD driver disabled
5. Scheduled task created (XML, runs on battery)
6. WinLogon login screen message set
7. System shutdown or reboot

### Phase 2 - Execution (SYSTEM, After Boot)
1. **Backup**: Registry hives, profile hives, DPAPI keys, browser profiles
2. **SID Change**:
   - SAM hive binary patch (dynamic offset detection)
   - SAM group membership patch (Administrators, Users, etc.)
   - SECURITY hive (LsaSetInformationPolicy)
   - ProfileList remapping (including orphan profile cleanup)
   - Registry key security descriptor patching (all hives + user hives)
   - LSA account rights migration
   - Registry SID string replacement (SOFTWARE, SYSTEM)
   - Service logon SID update
   - Scheduled Task XML SID update (encoding-safe)
3. **Profile Migration**: DPAPI key folder rename, Chromium machine ID cleanup, file ACLs
4. **Identity Reset**: MachineGuid, MachineId, WSUS, MSDTC, DeviceId, DHCP DUID
5. **Cleanup**: Icon cache, shell bags, TrayNotify, AppxAllUserStore
6. **Reboot**: 4-tier fallback (shutdown.exe -> InitiateSystemShutdownEx -> ExitWindowsEx -> NtShutdownSystem)

## Known Limitations

| Limitation | Description | Workaround |
|------------|-------------|------------|
| **Default apps** | UserChoice hashes are SID-bound, Windows hash algorithm is proprietary | Re-set defaults in Settings > Default Apps after reboot |
| **Chrome/Edge profiles** | DPAPI encryption is SID-bound, saved passwords are lost | Enable Chrome Sync before SID change |
| **Active Directory** | Domain trust relationship breaks | Leave domain first, rejoin after SID change |
| **BitLocker** | TPM detects registry changes as tampering | Disable BitLocker before running EASYSID |

## Build

```bash
# Development
dotnet build -c Release

# Self-contained single file
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:PublishTrimmed=true -o ./publish
```

GitHub Actions automatically builds and uploads to [Releases](https://github.com/bilalcaliskan58/EASYSID/releases) on every commit.

## License

This project is licensed under the [MIT License](LICENSE).
