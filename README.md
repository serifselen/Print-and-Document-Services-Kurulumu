# 🖨️ Windows Server Print and Document Services Kurulumu

Bu rehber, Windows Server 2019/2022 sistemine Print and Document Services rolünün nasıl kurulacağını ve ağ yazıcısı ekleme işlemlerini adım adım açıklar. Kurulum, Server Manager aracılığıyla gerçekleştirilir.

## 📋 İçindekiler

- [Ön Gereksinimler ve Hazırlık](#-ön-gereksinimler-ve-hazırlık)
- [Print and Document Services Kurulum Adımları](#-print-and-document-services-kurulum-adımları)
  - [Adım 1: Server Manager'dan Role Ekleme](#adım-1-server-managerdan-role-ekleme)
  - [Adım 2: Gerekli Yönetim Araçlarının Eklenmesi](#adım-2-gerekli-yönetim-araçlarının-eklenmesi)
  - [Adım 3: Print and Document Services Yapılandırması](#adım-3-print-and-document-services-yapılandırması)
  - [Adım 4: Role Services Seçimi](#adım-4-role-services-seçimi)
  - [Adım 5: Kurulum Onayı](#adım-5-kurulum-onayı)
- [Print Management Konsolu](#-print-management-konsolu)
  - [Adım 6: Print Management'ı Açma](#adım-6-print-managementı-açma)
  - [Adım 7: Mevcut Yazıcı Durumu](#adım-7-mevcut-yazıcı-durumu)
- [Ağ Yazıcısı Ekleme](#-ağ-yazıcısı-ekleme)
  - [Adım 8: Network Printer Installation Wizard Başlatma](#adım-8-network-printer-installation-wizard-başlatma)
  - [Adım 9: Yazıcı Kurulum Yöntemi Seçimi](#adım-9-yazıcı-kurulum-yöntemi-seçimi)
  - [Adım 10: Yazıcı IP Adresi Girişi](#adım-10-yazıcı-ip-adresi-girişi)
  - [Adım 11: Yazıcı Sürücüsü Seçimi](#adım-11-yazıcı-sürücüsü-seçimi)
  - [Adım 12: Yazıcı Üreticisi ve Modeli Seçimi](#adım-12-yazıcı-üreticisi-ve-modeli-seçimi)
  - [Adım 13: Yazıcı Adı ve Paylaşım Ayarları](#adım-13-yazıcı-adı-ve-paylaşım-ayarları)
  - [Adım 14: Kurulum Tamamlanması](#adım-14-kurulum-tamamlanması)
- [Yazıcı Yönetimi](#-yazıcı-yönetimi)
- [PowerShell ile Otomasyon](#-powershell-ile-otomasyon)
- [Sık Karşılaşılan Sorunlar ve Çözümler](#-sık-karşılaşılan-sorunlar-ve-çözümler)
- [En İyi Uygulamalar](#-en-iyi-uygulamalar)
- [Doküman Bilgileri](#-doküman-bilgileri)

---

## 🎯 Ön Gereksinimler ve Hazırlık

### Sistem Gereksinimleri

- **İşletim Sistemi:** Windows Server 2019/2022 Standard/Datacenter
- **Bellek:** Minimum 2 GB (Önerilen 4+ GB)
- **Depolama:** Minimum 10 GB boş alan
- **Ağ:** Statik IP adresi ve yazıcı IP bilgisi

### Kurulum Öncesi Hazırlık

**Teknik Doğrulama Komutları:**

```powershell
# IP yapılandırmasını kontrol et
Get-NetIPConfiguration

# Yazıcı IP adresine erişim kontrolü
Test-NetConnection -ComputerName "192.168.31.201" -Port 9100

# Windows Update durumunu kontrol et
Get-WindowsUpdateLog
```

**Kritik Ön Kontroller:**
- ✅ Statik IP yapılandırması doğrulanmalı
- ✅ Yazıcı ağ bağlantısı test edilmeli
- ✅ Güvenlik duvarı port kontrolleri yapılmalı
- ✅ Yönetici (Administrator) yetkisi olmalı

---

## 📦 Print and Document Services Kurulum Adımları

### Adım 1: Server Manager'dan Role Ekleme

**Server Manager** açıldığında **Dashboard** ekranından işlemlere başlanır.

**Teknik Detaylar:**
- Server Core kurulumunda PowerShell veya sconfig kullanılır
- GUI modunda Server Manager otomatik başlar
- Rol bazlı kurulum için temel arayüz

1. **Dashboard** üzerinden **Add Roles and Features Wizard** bağlantısına tıklayın
2. **Server Roles** sekmesine gelindiğinde **Print and Document Services** seçeneğini işaretleyin

**PowerShell Alternatifi:**

```powershell
# Print and Document Services rolünü PowerShell ile ekleme
Install-WindowsFeature -Name Print-Services -IncludeManagementTools

# Rol kurulum durumunu kontrol etme
Get-WindowsFeature -Name Print-Services
```

**📷 Referans:** `2.png` - Server Manager Dashboard ve "Add Roles and Features Wizard" ekranı

---

### Adım 2: Gerekli Yönetim Araçlarının Eklenmesi

Rol eklendikten sonra sistem otomatik olarak gerekli yönetim araçlarını kurmak için onay ister.

**Add features that are required for Print and Document Services** penceresi açılır.

**Yüklenen Bileşenler:**
- **Remote Server Administration Tools:** Uzaktan yönetim araçları
- **Role Administration Tools:** Rol yönetim araçları
- **Print and Document Services Tools:** Yazıcı yönetim konsolu

**Teknik Özellikler:**
- Print Management Console (printmanagement.msc)
- Print PowerShell Module
- RSAT araçları

✅ **Include management tools (if applicable)** seçeneği işaretli olarak **Add Features** butonuna tıklayın.

**PowerShell ile Yönetim Araçları Yükleme:**

```powershell
# Yönetim araçlarını dahil ederek kurulum
Install-WindowsFeature -Name Print-Services -IncludeManagementTools

# Print yönetim modülünü import etme
Import-Module PrintManagement

# Kullanılabilir cmdlet'leri listele
Get-Command -Module PrintManagement
```

**📷 Referans:** `3.png` - Management tools onay ekranı

---

### Adım 3: Print and Document Services Yapılandırması

**Print and Document Services** yapılandırma ekranında önemli notlar yer alır.

**Things to Note:**

**📌 Windows Server 2025 Yazıcı Sürücüleri:**
- Windows Server 2025, Type 3 veya Type 4 yazıcı sürücülerini destekler
- Microsoft, Type 4 yazıcı sürücülerinin kullanılmasını önerir
- Type 4 sürücüler kullanıldığında, domain üyesi olmayan 32-bit istemciler yazıcıya bağlanabilir

**🔒 Güvenlik Gereksinimleri:**
- İmzalı, paket tabanlı sürücüler kullanılmalıdır
- İmzasız sürücüler kullanılacaksa GPO ile "Computer\Administrative Templates\Printers\Point and Print Restrictions" yapılandırılmalıdır
- İstemciler yerel yönetici olmalı veya güvenlik politikası ayarlanmalıdır

**📝 Type 3 vs Type 4 Sürücüler:**

| Özellik | Type 3 (v3) | Type 4 (v4) |
|---------|-------------|-------------|
| Mimari | Kernel-mode | User-mode |
| 32-bit Desteği | Zorunlu | Opsiyonel |
| Güvenlik | Düşük | Yüksek |
| Kararlılık | Orta | Yüksek |
| Windows 10/11 | Desteklenir | Önerilen |

**Next** butonuna tıklanarak devam edilir.

**📷 Referans:** `4.png` - Print and Document Services bilgilendirme ekranı

---

### Adım 4: Role Services Seçimi

**Select role services to install for Print and Document Services** ekranında aşağıdaki servisler seçilir:

**Seçilen Role Services:**

- ✅ **Print Server**
  - Line Printer Daemon (LPD) Service
  - Merkezi yazıcı yönetimi ve paylaşım servisi

- ✅ **Internet Printing**
  - UNIX tabanlı bilgisayarlar için yazıcı servisi
  - HTTP/HTTPS üzerinden yazdırma desteği
  - IPP (Internet Printing Protocol) desteği

- ✅ **LPD Service**
  - Line Printer Remote (LPR) servisi
  - UNIX/Linux sistemlerle uyumluluk

**Otomatik Eklenen Bağımlılıklar:**

**Web Server Role (IIS)** otomatik olarak eklenir ve şu bileşenleri içerir:
- IIS Web Server
- ASP.NET 4.8
- .NET Framework 4.8 Features

**Servis Teknik Detayları:**

```powershell
# Print Server servisini başlatma/durdurma
Start-Service Spooler
Stop-Service Spooler

# LPD servisini etkinleştirme
Enable-WindowsOptionalFeature -Online -FeatureName LPDPrintService

# Internet Printing kontrolü
Get-WindowsFeature -Name Print-Internet
```

**Port Gereksinimleri:**

| Servis | Port | Protokol | Açıklama |
|--------|------|----------|----------|
| Print Server | 445 | TCP | SMB/CIFS |
| LPD Service | 515 | TCP | LPR/LPD |
| Internet Printing | 80/443 | TCP | HTTP/HTTPS |
| Raw Printing | 9100 | TCP | Direct IP |

**Next** butonuna tıklanarak devam edilir.

**📷 Referans:** `5.png` - Role Services seçim ekranı

---

### Adım 5: Kurulum Onayı

**Confirm installation selections** ekranında kurulacak bileşenler listelenir:

**Kurulum Bileşenleri:**

```
.NET Framework 4.8 Features
├── ASP.NET 4.8

Print and Document Services
├── Internet Printing
├── LPD Service
└── Print Server

Remote Server Administration Tools
├── Role Administration Tools
└── Print and Document Services Tools

Web Server (IIS)
```

**Kurulum Seçenekleri:**

İsteğe bağlı olarak:
- ☐ **Export configuration settings** - Yapılandırma ayarlarını XML olarak dışa aktarma
- ☐ **Specify an alternate source path** - Alternatif kaynak yolu belirleme
- ☐ **Restart the destination server automatically if required** - Otomatik yeniden başlatma

**PowerShell ile Kurulum:**

```powershell
# Tek komutla tüm bileşenleri kurma
Install-WindowsFeature -Name Print-Services,Print-Internet,Print-LPD-Service -IncludeManagementTools -Restart

# Kurulum sonuç kontrolü
Get-WindowsFeature | Where-Object {$_.Name -like "Print*"} | Select-Object Name, InstallState
```

**Kurulum Doğrulama:**

```powershell
# Print Spooler servis durumu
Get-Service -Name Spooler | Select-Object Name, Status, StartType

# IIS durumu kontrolü
Get-Service -Name W3SVC | Select-Object Name, Status, StartType

# Event log kontrolü
Get-EventLog -LogName System -Source "Service Control Manager" -Newest 20 | Where-Object {$_.Message -like "*Print*"}
```

**Install** butonuna tıklanarak kurulum başlatılır.

**📷 Referans:** `6.png` - Installation confirmation ekranı

---

## 🖥️ Print Management Konsolu

### Adım 6: Print Management'ı Açma

Kurulum tamamlandıktan sonra **Windows Tools** menüsünden **Print Management** konsolu açılır.

**Erişim Yolları:**

1. **Start Menu → Windows Tools → Print Management**
2. **Start → Run → printmanagement.msc**
3. **Server Manager → Tools → Print Management**
4. **PowerShell:** `& printmanagement.msc`

**Konsol Yapısı:**

```
Print Management
├── Custom Filters
│   ├── All Printers
│   ├── All Drivers
│   ├── Printers Not Ready
│   └── Printers With Jobs
├── Print Servers
│   └── DOMAIN (local)
│       ├── Drivers
│       ├── Forms
│       ├── Ports
│       └── Printers
└── Deployed Printers
```

**Konsol Özellikleri:**

- **Custom Filters:** Özel yazıcı filtreleri oluşturma
- **Print Servers:** Merkezi yazıcı sunucuları yönetimi
- **Deployed Printers:** GPO ile dağıtılan yazıcılar
- **Forms:** Kağıt boyutları ve form tanımları

**PowerShell Konsol Komutları:**

```powershell
# Print Management konsolunu açma
printmanagement.msc

# Tüm yazıcıları listeleme
Get-Printer | Format-Table Name, DriverName, PortName, Shared

# Yazıcı sayısı raporu
Get-Printer | Measure-Object | Select-Object Count

# Yazıcı durumu kontrol
Get-Printer | Select-Object Name, PrinterStatus, JobCount
```

**📷 Referans:** `7.png` - Windows Tools menüsü ve Print Management erişimi

---

### Adım 7: Mevcut Yazıcı Durumu

Print Management konsolunda varsayılan olarak **Microsoft Print to PDF** yazıcısı görüntülenir.

**Varsayılan Yazıcı Bilgileri:**

| Özellik | Değer |
|---------|-------|
| **Printer Name** | Microsoft Print to PDF |
| **Queue Status** | Ready |
| **Jobs In Queue** | 0 |
| **Server Name** | DOMAIN (local) |
| **Driver Name** | Microsoft Print To PDF |
| **Driver Version** | 10.0.26100.4484 |
| **Driver Type** | Type 4 - User Mode |

**Yazıcı Durumları:**

| Status | Anlamı | Aksiyon |
|--------|--------|---------|
| Ready | Hazır | Normal çalışma |
| Offline | Çevrimdışı | Bağlantı kontrolü |
| Paused | Duraklatılmış | Manuel müdahale |
| Error | Hata | Troubleshooting gerekli |

**PowerShell ile Yazıcı Sorguları:**

```powershell
# Tüm yazıcıları detaylı listeleme
Get-Printer | Select-Object Name, DriverName, PortName, ShareName, Published, Shared

# PDF yazıcı kontrolü
Get-Printer -Name "Microsoft Print to PDF" | Format-List *

# Yazıcı sürücü bilgisi
Get-PrinterDriver | Select-Object Name, Manufacturer, PrinterEnvironment
```

**📷 Referans:** `8.png` - Print Management konsolu ana ekranı

---

## 🌐 Ağ Yazıcısı Ekleme

### Adım 8: Network Printer Installation Wizard Başlatma

Print Management konsolunda **Printers** klasörüne sağ tıklanır ve **Add Printer...** seçeneği seçilir.

**Sağ Tık Menü Seçenekleri:**

- **Add Printer...** - Yeni yazıcı ekleme
- **Show Extended View** - Genişletilmiş görünüm
- **Refresh** - Listeyi yenileme
- **Export List...** - Yazıcı listesi dışa aktarma
- **View** - Görünüm seçenekleri
- **Arrange Icons** - İkon düzenleme
- **Line up Icons** - İkonları hizalama
- **Help** - Yardım menüsü

**PowerShell ile Yazıcı Ekleme Alternatifi:**

```powershell
# TCP/IP yazıcı portu oluşturma
Add-PrinterPort -Name "IP_192.168.31.201" -PrinterHostAddress "192.168.31.201" -PortNumber 9100

# Yazıcı sürücüsü yükleme
Add-PrinterDriver -Name "Microsoft XPS Document Writer v4"

# Yazıcı ekleme
Add-Printer -Name "Network Printer" -DriverName "Microsoft XPS Document Writer v4" -PortName "IP_192.168.31.201"
```

**📷 Referans:** `9.png` - Sağ tık menüsü ve Add Printer seçeneği

---

### Adım 9: Yazıcı Kurulum Yöntemi Seçimi

**Printer Installation - Pick an installation method** ekranında aşağıdaki seçenekler sunulur:

**Kurulum Yöntemleri:**

1. ⚪ **Search the network for printers**
   - Ağ taraması ile otomatik yazıcı keşfi
   - WSD ve Bonjour protokolleri desteği

2. 🔵 **Add an IPP, TCP/IP, or Web Services Printer by IP address or hostname**
   - Manuel IP adresi girişi (Önerilen)
   - IPP, RAW, LPR protokol desteği
   - DNS hostname veya IP kullanımı

3. ⚪ **Add a new printer using an existing port**
   - Mevcut port üzerinden yazıcı ekleme
   - LPT1, COM1, FILE portları

4. ⚪ **Create a new port and add a new printer**
   - Yeni port oluşturma (Local Port)
   - Custom port tanımlama

**Protokol Karşılaştırması:**

| Protokol | Port | Hız | Platform Desteği |
|----------|------|-----|------------------|
| RAW | 9100 | Hızlı | Tüm platformlar |
| LPR | 515 | Orta | UNIX/Linux/Windows |
| IPP | 631 | Orta | Modern sistemler |
| WSD | - | Orta | Windows only |

**🔵 Add an IPP, TCP/IP, or Web Services Printer** seçeneği işaretlenerek **Next** butonuna tıklanır.

**PowerShell Port Yönetimi:**

```powershell
# Mevcut portları listeleme
Get-PrinterPort | Select-Object Name, Description, PortMonitor

# TCP/IP port oluşturma
Add-PrinterPort -Name "IP_192.168.31.201" -PrinterHostAddress "192.168.31.201"

# LPR port oluşturma
Add-PrinterPort -Name "LPR_192.168.31.201" -LprHostAddress "192.168.31.201" -LprQueue "PASSTHRU"
```

**📷 Referans:** `10.png` - Printer Installation yöntem seçimi

---

### Adım 10: Yazıcı IP Adresi Girişi

**Printer Address** ekranında yazıcı ağ bilgileri girilir.

**Yapılandırma Parametreleri:**

**Type of Device:** `TCP/IP Device`

**Cihaz Türü Seçenekleri:**
- **TCP/IP Device** - Standart ağ yazıcıları (RAW/LPR)
- **Web Services Device** - WS-Print protokolü
- **IPP Device** - Internet Printing Protocol

**Host name or IP address:** `192.168.31.201`

- IP adresi veya DNS hostname girilebilir
- Örnek: `printer.domain.local` veya `192.168.31.201`

**Port name:** `192.168.31.201` (Otomatik doldurulur)

- Port adı otomatik oluşturulur
- Manuel düzenlenebilir

✅ **Auto detect the printer driver to use** seçeneği işaretlenir

- Yazıcı modeli otomatik algılanır
- SNMP protokolü kullanılır
- Desteklenen sürücü otomatik seçilir

**Teknik Notlar:**

💡 **Autodetect Özellikleri:**
- WSD (Web Services for Devices) yazıcıları algılar
- TCP/IP (RAW port 9100) yazıcıları algılar
- SNMP ile yazıcı model bilgisi alır
- IPP yazıcı aramak için **Type of Device** dropdown'ından IPP seçilmelidir

**SNMP Ayarları:**

```powershell
# SNMP bilgisi ile yazıcı ekleme
Add-PrinterPort -Name "IP_192.168.31.201" -PrinterHostAddress "192.168.31.201" -SNMPEnabled $true -SNMPCommunity "public"

# Port yapılandırmasını kontrol etme
Get-PrinterPort -Name "IP_192.168.31.201" | Format-List *
```

**Bağlantı Testi:**

```powershell
# Yazıcı IP erişim kontrolü
Test-NetConnection -ComputerName "192.168.31.201" -Port 9100

# Ping testi
Test-Connection -ComputerName "192.168.31.201" -Count 4

# SNMP testi
Test-NetConnection -ComputerName "192.168.31.201" -Port 161
```

**Next** butonuna tıklanarak devam edilir.

**📷 Referans:** `11.png` - Printer Address girişi

---

### Adım 11: Yazıcı Sürücüsü Seçimi

**Printer Driver** ekranında üç seçenek sunulur:

**Sürücü Seçim Yöntemleri:**

1. ⚪ **Use the printer driver that the wizard selected**
   - Autodetect ile bulunan sürücü (Önerilen)
   - *Compatible driver cannot be found.* - Eğer algılanmadıysa

2. ⚪ **Use an existing printer driver on the computer**
   - Sistemde yüklü sürücüler kullanılır
   - Dropdown listeden seçim yapılır
   - Örnek: `Microsoft IPP Class Driver`

3. 🔵 **Install a new driver**
   - Yeni sürücü kurulumu
   - Windows Update'ten veya disk'ten yükleme
   - Üretici sürücü dosyası ekleme

**Sürücü Sınıfları:**

| Driver Class | Açıklama | Kullanım Senaryosu |
|--------------|----------|---------------------|
| Universal Printer Driver | Microsoft PCL/XPS | Generic yazıcılar |
| Manufacturer Driver | Üretici özgün sürücü | Gelişmiş özellikler |
| PostScript Driver | PS dil desteği | Profesyonel baskı |
| PCL Driver | HP Printer Language | HP ve uyumlu |

**🔵 Install a new driver** seçeneği işaretlenerek **Next** butonuna tıklanır.

**PowerShell ile Sürücü Yönetimi:**

```powershell
# Yüklü sürücüleri listeleme
Get-PrinterDriver | Select-Object Name, PrinterEnvironment, DriverVersion

# Sürücü bilgisi detaylı
Get-PrinterDriver -Name "Microsoft XPS Document Writer v4" | Format-List *

# Sürücü yükleme (INF dosyasından)
Add-PrinterDriver -Name "HP LaserJet P3015" -InfPath "C:\Drivers\HP\hpbx3w81.inf"
```

**📷 Referans:** `12.png` - Printer Driver seçimi

---

### Adım 12: Yazıcı Üreticisi ve Modeli Seçimi

**Printer Installation - Select the manufacturer and model of your printer** ekranında sürücü seçilir.

**Sürücü Seçim Ekranı:**

**Manufacturer (Üretici) Listesi:**
- Generic
- 🔵 **Microsoft**
- HP
- Canon
- Epson
- Brother
- Xerox
- Ricoh
- Kyocera

**Microsoft Printers (Sürücü Listesi):**

| Sürücü Adı | Açıklama | Kullanım |
|------------|----------|----------|
| **Microsoft MS-XPS Class Driver 2** ✅ | XPS belge desteği | Genel amaçlı |
| Microsoft OpenXPS Class Driver | Open XPS formatı | Modern sistemler |
| Microsoft OpenXPS Class Driver 2 | Geliştirilmiş OpenXPS | Windows 10+ |
| Microsoft PCL6 Class Driver | HP PCL6 dil | HP uyumlu |
| Microsoft PS Class Driver | PostScript dil | Profesyonel |

**Bu örnekte `Microsoft MS-XPS Class Driver 2` seçilir.**

**Dijital İmza Doğrulaması:**

✅ **This driver is digitally signed**
- Microsoft tarafından imzalanmış
- Windows Hardware Quality Labs (WHQL) onaylı
- Güvenli ve kararlı

**🔗 Tell me why driver signing is important** - Dijital imza önem açıklaması

**Alternatif Yükleme Seçenekleri:**

- **Windows Update** - Güncel sürücüler için online arama
- **Have Disk...** - CD/DVD/USB'den manuel yükleme

**PowerShell ile Sürücü Kurulumu:**

```powershell
# Microsoft XPS sürücüsü yükleme
Add-PrinterDriver -Name "Microsoft XPS Document Writer v4"

# Üretici sürücüsü yükleme (INF ile)
pnputil /add-driver "C:\Drivers\HP\hpbx3w81.inf" /install
Add-PrinterDriver -Name "HP LaserJet P3015"

# Windows Update'ten sürücü arama
Get-PrinterDriver | Where-Object {$_.Manufacturer -like "*Microsoft*"}
```

**Sürücü Uyumluluk Matrisi:**

| Windows Version | Type 3 | Type 4 | Universal |
|----------------|--------|--------|-----------|
| Server 2019 | ✅ | ✅ | ✅ |
| Server 2022 | ⚠️ | ✅ | ✅ |
| Server 2025 | ❌ | ✅ | ✅ |

**Next** butonuna tıklanarak devam edilir.

**📷 Referans:** `13.png` - Manufacturer ve model seçimi

---

### Adım 13: Yazıcı Adı ve Paylaşım Ayarları

**Printer Name and Sharing Settings** ekranında yazıcı tanımlanır.

**Yazıcı Yapılandırma Parametreleri:**

**Printer Name:** `Microsoft MS-XPS Class Driver 2`

- Yazıcı görünen adı (Display Name)
- Kullanıcıların göreceği isim
- 260 karakter limiti
- Özel karakterler kullanılabilir

✅ **Share this printer** işaretlenir

- Ağ paylaşımı etkinleştirilir
- SMB/CIFS protokolü kullanılır
- Domain kullanıcıları erişebilir

**Share Name:** `Microsoft MS-XPS Class Driver 2`

- NetBIOS paylaşım adı
- 80 karakter limiti
- Boşluk yerine "_" önerilir
- UNC yolu: `\\DOMAIN\Microsoft MS-XPS Class Driver 2`

**Location:** (Opsiyonel)

- Yazıcının fiziksel konumu
- Örnek: "3rd Floor, Room 301"
- AD Location özelliği ile senkronize
- Arama filtresi için kullanılır

**Comment:** (Opsiyonel)

- Yazıcı açıklaması
- Model, özellikler, kısıtlamalar
- Kullanıcı bilgilendirmesi
- Örnek: "Color printer - Duplex enabled"

**Adlandırma Best Practices:**

```
Standart Format: [Lokasyon]-[Departman]-[Tip]-[Model]
Örnekler:
- ANKARA-IT-COLOR-HP4015
- ISTANBUL-FINANCE-BW-XEROX5555
- IZMIR-HR-MULTIFUNC-RICOH3045
```

**PowerShell ile Paylaşım Yapılandırması:**

```powershell
# Yazıcı paylaşım ayarları
Set-Printer -Name "Microsoft MS-XPS Class Driver 2" -Shared $true -ShareName "MS-XPS-CLR2"

# Location ve Comment ekleme
Set-Printer -Name "Microsoft MS-XPS Class Driver 2" -Location "Building A, 2nd Floor" -Comment "Network XPS Printer"

# Yazıcıyı Active Directory'ye yayınlama
Set-Printer -Name "Microsoft MS-XPS Class Driver 2" -Published $true

# UNC yolu oluşturma
$UNCPath = "\\$env:COMPUTERNAME\MS-XPS-CLR2"
Write-Host "Yazıcı UNC Yolu: $UNCPath"
```

**Active Directory Integration:**

```powershell
# Yazıcıyı AD'ye kaydetme
Set-Printer -Name "Microsoft MS-XPS Class Driver 2" -Published $true

# AD'de yazıcı arama
Get-ADObject -Filter 'objectClass -eq "printQueue"' -SearchBase "CN=Printers,DC=domain,DC=local"
```

**Next** butonuna tıklanarak kurulum tamamlanır.

**📷 Referans:** `14.png` - Printer Name and Sharing Settings

---

### Adım 14: Kurulum Tamamlanması

**Completing the Network Printer Installation Wizard** ekranında kurulum sonucu görüntülenir.

**Kurulum Durumu:**

**Status:**
- ✅ **Driver installation succeeded.**
  - Yazıcı sürücüsü başarıyla yüklendi
  - Sürücü dosyaları kopyalandı
  - Registry kayıtları oluşturuldu

- ✅ **Printer installation succeeded.**
  - Yazıcı başarıyla eklendi
  - Port yapılandırması tamamlandı
  - Paylaşım ayarları uygulandı

**✅ Your printer has been installed successfully.**

**Kurulum Sonrası Seçenekler:**

☐ **Print test page**
- Test sayfası yazdırma
- Yazıcı bağlantısı doğrulama
- Renk/kalite kontrolü
- Sorun giderme aracı

☐ **Add another printer**
- Hızlı çoklu yazıcı ekleme
- Wizard'ı yeniden başlatma
- Toplu kurulum için kullanışlı

**Finish** butonuna tıklanarak işlem tamamlanır.

**Kurulum Doğrulama:**

```powershell
# Yeni eklenen yazıcıyı kontrol et
Get-Printer -Name "Microsoft MS-XPS Class Driver 2" | Format-List *

# Yazıcı durumunu test et
Test-Connection -ComputerName "192.168.31.201" -Count 2
Get-Printer -Name "Microsoft MS-XPS Class Driver 2" | Select-Object Name, PrinterStatus, JobCount

# Test sayfası yazdırma
$printer = Get-Printer -Name "Microsoft MS-XPS Class Driver 2"
Start-Process -FilePath "rundll32.exe" -ArgumentList "printui.dll,PrintUIEntry /k /n ""$($printer.Name)"""

# Print Management'ta görüntüleme
Get-Printer | Where-Object {$_.ComputerName -eq $env:COMPUTERNAME}
```

**Event Log Kontrolü:**

```powershell
# Yazıcı kurulum event'lerini görüntüleme
Get-EventLog -LogName System -Source "Print" -Newest 10

# Microsoft-Windows-PrintService event log
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Admin" -MaxEvents 20
```

**📷 Referans:** `1.png` - Completing the Network Printer Installation Wizard

---

## 🛠️ Yazıcı Yönetimi

Kurulum tamamlandıktan sonra yeni yazıcı Print Management konsolunda görüntülenir ve aşağıdaki işlemler yapılabilir:

### Temel Yönetim İşlemleri

**Yazıcı Özellikleri:**

```powershell
# Yazıcı özelliklerini görüntüleme
Get-Printer -Name "Microsoft MS-XPS Class Driver 2" | Format-List *

# Yazıcı güvenlik ayarları
Get-PrinterSecurityDescriptor -PrinterName "Microsoft MS-XPS Class Driver 2"

# Yazıcı izinlerini düzenleme
Set-PrinterPermission -PrinterName "Microsoft MS-XPS Class Driver 2" -UserName "DOMAIN\Finance-Users" -AccessRight "Print"
```

**Yazıcı Kuyruğu Yönetimi:**

```powershell
# Print queue'daki işleri görüntüleme
Get-PrintJob -PrinterName "Microsoft MS-XPS Class Driver 2"

# Tüm işleri temizleme
Get-PrintJob -PrinterName "Microsoft MS-XPS Class Driver 2" | Remove-PrintJob

# Yazıcıyı duraklatma/devam ettirme
Suspend-PrintJob -PrinterName "Microsoft MS-XPS Class Driver 2"
Resume-PrintJob -PrinterName "Microsoft MS-XPS Class Driver 2"
```

### Kullanıcı İzinleri

**İzin Seviyeleri:**

| İzin | Print | Manage Printer | Manage Documents |
|------|-------|----------------|------------------|
| **Print** | ✅ | ❌ | ❌ |
| **Manage this printer** | ✅ | ✅ | ❌ |
| **Manage documents** | ✅ | ❌ | ✅ |

**PowerShell İzin Yönetimi:**

```powershell
# Domain Users'a print izni verme
$acl = Get-PrinterSecurityDescriptor -PrinterName "Microsoft MS-XPS Class Driver 2"
# ACL düzenleme ve uygulama
Set-PrinterSecurityDescriptor -PrinterName "Microsoft MS-XPS Class Driver 2" -SecurityDescriptor $acl

# Grup bazlı izin ekleme
Add-PrinterSecurityDescriptor -PrinterName "Microsoft MS-XPS Class Driver 2" -User "DOMAIN\IT-Team" -AccessRight ManagePrinter
```

### Yazdırma İşi İzleme

**Monitoring ve Raporlama:**

```powershell
# Gerçek zamanlı izleme scripti
while ($true) {
    $jobs = Get-PrintJob -PrinterName "Microsoft MS-XPS Class Driver 2"
    Write-Host "Active Jobs: $($jobs.Count)" -ForegroundColor Green
    $jobs | Format-Table JobName, UserName, Size, JobStatus
    Start-Sleep -Seconds 5
    Clear-Host
}

# Günlük yazdırma raporu
$StartDate = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PrintService/Operational'
    StartTime = $StartDate
} | Where-Object {$_.Id -eq 307} | 
Select-Object TimeCreated, Message | 
Export-Csv -Path "C:\PrintLog_$(Get-Date -Format 'yyyyMMdd').csv"
```

### Domain Üzerinden Dağıtım (Deploy)

**Group Policy ile Yazıcı Dağıtımı:**

```powershell
# Print Management'tan GPO ile dağıtım
# 1. Print Management Console'da yazıcıya sağ tık
# 2. "Deploy with Group Policy..." seçeneğini seç
# 3. GPO seç veya oluştur
# 4. Per User veya Per Computer seç
# 5. Apply

# PowerShell ile GPO printer deployment
$GPO = Get-GPO -Name "Printer Deployment Policy"
Set-GPPrefRegistryValue -Name "Printer Deployment Policy" `
    -Context User -Action Create `
    -Key "HKCU\Printers\Connections" `
    -ValueName "\\DOMAIN\Microsoft MS-XPS Class Driver 2" `
    -Type String -Value ""
```

**Deployment Script:**

```powershell
# Toplu kullanıcılara yazıcı dağıtımı
$Printers = @(
    "\\DOMAIN\Microsoft MS-XPS Class Driver 2",
    "\\DOMAIN\Finance-Printer",
    "\\DOMAIN\HR-Printer"
)

foreach ($Printer in $Printers) {
    try {
        Add-Printer -ConnectionName $Printer
        Write-Host "Eklendi: $Printer" -ForegroundColor Green
    }
    catch {
        Write-Host "Hata: $Printer - $($_.Exception.Message)" -ForegroundColor Red
    }
}
```

---

## ⚙️ PowerShell ile Otomasyon

### Tam Otomatik Kurulum Scripti

```powershell
<#
.SYNOPSIS
    Windows Server Print and Document Services Otomatik Kurulum
.DESCRIPTION
    Print Services rolünü kurar, yazıcı ekler ve yapılandırır
.NOTES
    Yönetici yetkileri gereklidir
#>

# Print Services rolünü kurma
Write-Host "Print Services rolü kuruluyor..." -ForegroundColor Cyan
Install-WindowsFeature -Name Print-Services,Print-Internet,Print-LPD-Service -IncludeManagementTools -Restart:$false

# Print Management modülünü içe aktarma
Import-Module PrintManagement

# Yazıcı bilgileri
$PrinterConfig = @{
    Name = "Network-Printer-01"
    DriverName = "Microsoft XPS Document Writer v4"
    IPAddress = "192.168.31.201"
    PortName = "IP_192.168.31.201"
    ShareName = "NET-PRINT-01"
    Location = "Building A, Floor 2"
    Comment = "Network XPS Printer for Finance Department"
    Published = $true
}

# TCP/IP Port oluşturma
Write-Host "Yazıcı portu oluşturuluyor..." -ForegroundColor Cyan
Add-PrinterPort -Name $PrinterConfig.PortName `
    -PrinterHostAddress $PrinterConfig.IPAddress `
    -PortNumber 9100 `
    -SNMP $true `
    -SNMPCommunity "public"

# Sürücü yükleme
Write-Host "Yazıcı sürücüsü yükleniyor..." -ForegroundColor Cyan
Add-PrinterDriver -Name $PrinterConfig.DriverName

# Yazıcı ekleme
Write-Host "Yazıcı ekleniyor..." -ForegroundColor Cyan
Add-Printer -Name $PrinterConfig.Name `
    -DriverName $PrinterConfig.DriverName `
    -PortName $PrinterConfig.PortName `
    -Shared $true `
    -ShareName $PrinterConfig.ShareName `
    -Location $PrinterConfig.Location `
    -Comment $PrinterConfig.Comment `
    -Published $PrinterConfig.Published

# Yazıcı durumunu kontrol etme
$Printer = Get-Printer -Name $PrinterConfig.Name
if ($Printer) {
    Write-Host "✅ Yazıcı başarıyla eklendi!" -ForegroundColor Green
    $Printer | Format-List Name, DriverName, PortName, Shared, Published
} else {
    Write-Host "❌ Yazıcı eklenirken hata oluştu!" -ForegroundColor Red
}

# Test sayfası yazdırma fonksiyonu
function Print-TestPage {
    param([string]$PrinterName)
    
    $TestFile = "$env:TEMP\testpage.txt"
    "Print Test - $(Get-Date)" | Out-File -FilePath $TestFile
    Start-Process -FilePath "notepad.exe" -ArgumentList "/p $TestFile" -Wait
    Remove-Item -Path $TestFile -Force
}

# İsteğe bağlı test sayfası
# Print-TestPage -PrinterName $PrinterConfig.Name

Write-Host "`n✅ Kurulum tamamlandı!" -ForegroundColor Green
```

### Toplu Yazıcı Ekleme

```powershell
# CSV'den toplu yazıcı kurulumu
$Printers = Import-Csv -Path "C:\Printers.csv"

# CSV Format:
# Name,IPAddress,DriverName,Location,Department,ShareName

foreach ($Printer in $Printers) {
    $PortName = "IP_$($Printer.IPAddress)"
    
    # Port oluştur
    Add-PrinterPort -Name $PortName -PrinterHostAddress $Printer.IPAddress -ErrorAction SilentlyContinue
    
    # Yazıcı ekle
    Add-Printer -Name $Printer.Name `
        -DriverName $Printer.DriverName `
        -PortName $PortName `
        -Shared $true `
        -ShareName $Printer.ShareName `
        -Location $Printer.Location `
        -Comment "$($Printer.Department) Department Printer"
    
    Write-Host "✅ $($Printer.Name) eklendi" -ForegroundColor Green
}
```

### Yazıcı Sağlık Kontrolü

```powershell
# Tüm yazıcılar için sağlık kontrolü
function Test-PrinterHealth {
    $Printers = Get-Printer
    $Report = @()
    
    foreach ($Printer in $Printers) {
        $Status = @{
            Name = $Printer.Name
            Status = $Printer.PrinterStatus
            JobCount = (Get-PrintJob -PrinterName $Printer.Name).Count
            Shared = $Printer.Shared
            Published = $Printer.Published
        }
        
        # Port connectivity testi
        if ($Printer.PortName -match "IP_(.+)") {
            $IP = $Matches[1]
            $Status.Connectivity = (Test-NetConnection -ComputerName $IP -Port 9100 -InformationLevel Quiet)
        }
        
        $Report += New-Object PSObject -Property $Status
    }
    
    return $Report | Format-Table -AutoSize
}

# Raporu çalıştırma
Test-PrinterHealth
```

### Yazıcı Yedekleme ve Geri Yükleme

```powershell
# Yazıcı yapılandırmasını yedekleme
function Backup-PrinterConfiguration {
    param([string]$BackupPath = "C:\PrinterBackup")
    
    if (-not (Test-Path $BackupPath)) {
        New-Item -Path $BackupPath -ItemType Directory | Out-Null
    }
    
    # Yazıcıları dışa aktarma
    Get-Printer | Export-Clixml -Path "$BackupPath\Printers_$(Get-Date -Format 'yyyyMMdd').xml"
    
    # Portları dışa aktarma
    Get-PrinterPort | Export-Clixml -Path "$BackupPath\PrinterPorts_$(Get-Date -Format 'yyyyMMdd').xml"
    
    # Sürücüleri dışa aktarma
    Get-PrinterDriver | Export-Clixml -Path "$BackupPath\PrinterDrivers_$(Get-Date -Format 'yyyyMMdd').xml"
    
    Write-Host "✅ Yedekleme tamamlandı: $BackupPath" -ForegroundColor Green
}

# Yazıcı yapılandırmasını geri yükleme
function Restore-PrinterConfiguration {
    param([string]$BackupPath)
    
    # Portları içe aktarma
    $Ports = Import-Clixml -Path "$BackupPath\PrinterPorts_*.xml" | Select-Object -First 1
    foreach ($Port in $Ports) {
        Add-PrinterPort -Name $Port.Name -PrinterHostAddress $Port.PrinterHostAddress -ErrorAction SilentlyContinue
    }
    
    # Sürücüleri içe aktarma
    $Drivers = Import-Clixml -Path "$BackupPath\PrinterDrivers_*.xml" | Select-Object -First 1
    foreach ($Driver in $Drivers) {
        Add-PrinterDriver -Name $Driver.Name -ErrorAction SilentlyContinue
    }
    
    # Yazıcıları içe aktarma
    $Printers = Import-Clixml -Path "$BackupPath\Printers_*.xml" | Select-Object -First 1
    foreach ($Printer in $Printers) {
        Add-Printer -Name $Printer.Name `
            -DriverName $Printer.DriverName `
            -PortName $Printer.PortName `
            -Shared $Printer.Shared `
            -ShareName $Printer.ShareName `
            -ErrorAction SilentlyContinue
    }
    
    Write-Host "✅ Geri yükleme tamamlandı!" -ForegroundColor Green
}

# Yedekleme çalıştırma
Backup-PrinterConfiguration -BackupPath "C:\PrinterBackup"
```

---

## 🔧 Sık Karşılaşılan Sorunlar ve Çözümler

### Sorun 1: Yazıcı Offline Görünüyor

**Belirtiler:**
- Yazıcı durumu "Offline" olarak görünüyor
- Yazdırma işleri kuyrukta bekliyor
- Ping atılıyor ancak yazıcı çalışmıyor

**Çözüm:**

```powershell
# Yazıcı durumunu kontrol et
Get-Printer -Name "Microsoft MS-XPS Class Driver 2" | Select-Object Name, PrinterStatus, DriverName

# Print Spooler servisini yeniden başlat
Restart-Service Spooler

# Port bağlantısını test et
Test-NetConnection -ComputerName "192.168.31.201" -Port 9100

# SNMP servisini kontrol et
Get-Service -Name SNMP | Restart-Service

# Yazıcıyı online hale getir
Set-Printer -Name "Microsoft MS-XPS Class Driver 2" -PrinterStatus Normal
```

**Alternatif Çözüm:**
1. Print Management Console → Yazıcıya sağ tık
2. **Use Printer Online** seçeneğini işaretle
3. Print Spooler servisini yeniden başlat

---

### Sorun 2: Sürücü Kurulum Hatası

**Belirtiler:**
- "Driver installation failed"
- "The specified driver is not compatible"
- Dijital imza hatası

**Çözüm:**

```powershell
# Mevcut sürücüleri listele
Get-PrinterDriver | Select-Object Name, PrinterEnvironment

# Eski sürücüyü kaldır
Remove-PrinterDriver -Name "Microsoft MS-XPS Class Driver 2" -RemoveFromDriverStore

# Print Spooler'ı temizle
Stop-Service Spooler
Remove-Item -Path "C:\Windows\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
Start-Service Spooler

# Yeni sürücü yükle
Add-PrinterDriver -Name "Microsoft XPS Document Writer v4"

# Driver signing policy kontrolü (Test ortamları için)
# bcdedit /set testsigning on
# bcdedit /set nointegritychecks on
```

---

### Sorun 3: Paylaşım Erişim Sorunu

**Belirtiler:**
- İstemciler yazıcıya erişemiyor
- "Access Denied" hatası
- UNC yolu çalışmıyor

**Çözüm:**

```powershell
# Paylaşım kontrolü
Get-Printer -Name "Microsoft MS-XPS Class Driver 2" | Select-Object Shared, ShareName

# SMB paylaşım ayarlarını kontrol et
Get-SmbShare

# Güvenlik duvarı kuralları
New-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)" `
    -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow

New-NetFirewallRule -DisplayName "Print Spooler Service (RPC)" `
    -Direction Inbound -Protocol TCP -LocalPort 135 -Action Allow

# Print Spooler güvenlik ayarları
Set-Service -Name Spooler -StartupType Automatic
sc.exe sdset Spooler "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"

# Yazıcı paylaşım izinlerini sıfırla
$acl = Get-PrinterSecurityDescriptor -PrinterName "Microsoft MS-XPS Class Driver 2"
# ACL'yi düzenle ve uygula
```

---

### Sorun 4: Print Queue Takılması

**Belirtiler:**
- Yazdırma işleri silinemiyor
- Spooler servisi sürekli durıyor
- Yazıcı kuyruk temizlenemiyor

**Çözüm:**

```powershell
# Agresif kuyruk temizleme scripti
function Clear-PrintQueue {
    param([string]$PrinterName)
    
    # Tüm işleri durdur
    Get-PrintJob -PrinterName $PrinterName | Remove-PrintJob -Confirm:$false
    
    # Spooler'ı durdur
    Stop-Service -Name Spooler -Force
    
    # Spool klasörünü temizle
    Remove-Item -Path "C:\Windows\System32\spool\PRINTERS\*" -Force -ErrorAction SilentlyContinue
    
    # Spooler'ı başlat
    Start-Service -Name Spooler
    
    # Yazıcıyı yeniden başlat
    Disable-Printer -Name $PrinterName
    Start-Sleep -Seconds 2
    Enable-Printer -Name $PrinterName
    
    Write-Host "✅ Print queue temizlendi" -ForegroundColor Green
}

# Kullanım
Clear-PrintQueue -PrinterName "Microsoft MS-XPS Class Driver 2"
```

---

### Sorun 5: DNS/NetBIOS İsim Çözümleme Sorunu

**Belirtiler:**
- `\\SERVERNAME\PrinterName` çalışmıyor
- IP ile erişim çalışıyor
- Client yazıcı bulamıyor

**Çözüm:**

```powershell
# DNS kaydını kontrol et
Resolve-DnsName -Name $env:COMPUTERNAME

# NetBIOS kontrolü
nbtstat -a $env:COMPUTERNAME

# WINS kaydını yenile
nbtstat -RR

# Hosts dosyasına ekleme (geçici çözüm)
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "192.168.31.100  DOMAIN"

# DNS Client cache temizleme
Clear-DnsClientCache

# NetBIOS over TCP/IP kontrolü
Get-NetAdapterBinding | Where-Object {$_.DisplayName -like "*NetBIOS*"}
```

---

## 📚 En İyi Uygulamalar

### Güvenlik

**1. Yazıcı Güvenliği:**

```powershell
# Güvenli yazıcı yapılandırması
Set-Printer -Name "Microsoft MS-XPS Class Driver 2" -PermissionSDDL "O:BAG:DUD:(A;;SWRC;;;BA)(A;;SW;;;WD)"

# Anonymous kullanıcıların erişimini engelle
Set-PrinterPermission -PrinterName "Microsoft MS-XPS Class Driver 2" -UserName "Everyone" -AccessRight None

# Denetim etkinleştirme
auditpol /set /subcategory:"Print Service" /success:enable /failure:enable
```

**2. Departman Bazlı İzinler:**

```powershell
# Finance departmanına özel izin
Set-PrinterPermission -PrinterName "Finance-Printer" -UserName "DOMAIN\Finance-Users" -AccessRight Print

# IT departmanına tam yönetim
Set-PrinterPermission -PrinterName "Finance-Printer" -UserName "DOMAIN\IT-Admins" -AccessRight ManagePrinter
```

### Performans Optimizasyonu

**1. Print Spooler Ayarları:**

```powershell
# Spooler thread sayısını artırma
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print" -Name "ServerThread" -Value 4

# Spooler timeout süresini ayarlama
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print" -Name "SpoolerTimeOut" -Value 600
```

**2. Spool Klasörü Optimizasyonu:**

```powershell
# Spool klasörünü farklı diske taşıma
$NewSpoolPath = "D:\PrintSpool"
New-Item -Path $NewSpoolPath -ItemType Directory -Force

Stop-Service Spooler
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Printers" `
    -Name "DefaultSpoolDirectory" -Value $NewSpoolPath
Start-Service Spooler
```

### Monitoring ve Raporlama

**1. Otomatik Sağlık Kontrolü:**

```powershell
# Scheduled Task ile otomatik monitoring
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File C:\Scripts\PrinterHealthCheck.ps1"

$Trigger = New-ScheduledTaskTrigger -Daily -At "08:00AM"

Register-ScheduledTask -TaskName "Printer Health Check" `
    -Action $Action -Trigger $Trigger -RunLevel Highest
```

**2. Günlük Yazdırma Raporu:**

```powershell
# Günlük yazdırma istatistikleri
$Report = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PrintService/Operational'
    StartTime = (Get-Date).AddDays(-1)
    ID = 307
} | Group-Object {$_.Properties[2].Value} | 
Select-Object @{N='Printer';E={$_.Name}}, @{N='JobCount';E={$_.Count}}

$Report | Export-Csv -Path "C:\Reports\DailyPrintReport_$(Get-Date -Format 'yyyyMMdd').csv"
```

### Yedekleme Stratejisi

**1. Düzenli Otomatik Yedekleme:**

```powershell
# Haftalık yedekleme task
$BackupScript = {
    $BackupPath = "\\FileServer\PrinterBackups\$(Get-Date -Format 'yyyyMMdd')"
    New-Item -Path $BackupPath -ItemType Directory -Force
    
    Get-Printer | Export-Clixml -Path "$BackupPath\Printers.xml"
    Get-PrinterPort | Export-Clixml -Path "$BackupPath\Ports.xml"
    Get-PrinterDriver | Export-Clixml -Path "$BackupPath\Drivers.xml"
    
    # Registry backup
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\Print" "$BackupPath\PrintRegistry.reg" /y
}

$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-Command $BackupScript"

$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "02:00AM"

Register-ScheduledTask -TaskName "Weekly Printer Backup" `
    -Action $Action -Trigger $Trigger -RunLevel Highest
```

### Dokümantasyon

**1. Yazıcı Envanteri:**

```powershell
# Detaylı yazıcı envanteri raporu
Get-Printer | Select-Object Name, DriverName, PortName, Location, Comment, Shared, Published |
Export-Csv -Path "C:\Reports\PrinterInventory_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# HTML rapor oluşturma
$HTML = Get-Printer | ConvertTo-Html -Property Name, DriverName, PortName, PrinterStatus, JobCount `
    -Title "Printer Inventory Report" -PreContent "<h1>Printer Inventory - $(Get-Date)</h1>"

$HTML | Out-File -FilePath "C:\Reports\PrinterInventory.html"
```

---

## 📄 Doküman Bilgileri

| Özellik | Değer |
|---------|-------|
| **Yazar** | Serif SELEN |
| **Tarih** | 4 Kasım 2025 |
| **Versiyon** | 1.0 |
| **Platform** | VMware Workstation Pro 17 |
| **İşletim Sistemi** | Windows Server 2019/2022 |
| **Yazıcı Model** | Generic Network Printer |
| **Yazıcı IP** | 192.168.31.201 |
| **Lisans** | Evaluation |

### Değişiklik Geçmişi

- **v1.0:** İlk sürüm - Print and Document Services kurulumu, ağ yazıcısı ekleme, PowerShell otomasyonu, sorun giderme

### Güvenlik Uyarısı

⚠️ **Bu doküman eğitim ve test ortamları için hazırlanmıştır.**

**Üretim Ortamı İçin:**
- Lisanslı Windows Server kullanın
- Güvenlik politikalarını uygulayın
- Düzenli yedekleme yapın
- Güvenlik duvarı kurallarını yapılandırın
- Denetim loglarını etkinleştirin
- Yazıcı sürücülerini güncel tutun

### Destek ve İletişim

📧 **E-posta:** mserifselen@gmail.com

🔗 **GitHub Repository:** [https://github.com/serifselen/Print-and-Document-Services-Kurulumu](https://github.com/serifselen)

###