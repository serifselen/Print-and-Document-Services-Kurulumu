# 🖨️ Windows Server Print and Document Services Kurulumu

Bu rehber, Windows Server 2019/2022 sistemine Print and Document Services rolünün nasıl kurulacağını ve ağ yazıcısı ekleme işlemlerini adım adım açıklar. Kurulum, Server Manager aracılığıyla gerçekleştirilir.

## 📋 İçindekiler

- [Ön Gereksinimler ve Hazırlık](#-ön-gereksinimler-ve-hazırlık)
- [Print and Document Services Kurulum Adımları](#-print-and-document-services-kurulum-adımları)
- [Print Management Konsolu](#-print-management-konsolu)
- [Ağ Yazıcısı Ekleme](#-ağ-yazıcısı-ekleme)
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

### Adım 1: Server Manager Dashboard ve Role Seçimi

**Server Manager** açıldığında **Dashboard** ekranından işlemlere başlanır.

![Server Manager - Select Server Roles](Images/2.png)
*Resim 2: Server Manager'da "Add Roles and Features Wizard" - Server Roles seçim ekranı. Print and Document Services ve DNS Server rollerinin seçildiği görülmekte.*

**Kurulum Adımları:**

1. **Server Manager** → **Dashboard** → **Add roles and features**
2. **Before You Begin** ekranında **Next**
3. **Installation Type** → **Role-based or feature-based installation** → **Next**
4. **Server Selection** → Hedef sunucuyu seçin → **Next**
5. **Server Roles** ekranında **Print and Document Services** işaretleyin

**Teknik Detaylar:**
- Server Core kurulumunda PowerShell veya sconfig kullanılır
- GUI modunda Server Manager otomatik başlar
- Rol bazlı kurulum için temel arayüz

**PowerShell Alternatifi:**

```powershell
# Print and Document Services rolünü PowerShell ile ekleme
Install-WindowsFeature -Name Print-Services -IncludeManagementTools

# Rol kurulum durumunu kontrol etme
Get-WindowsFeature -Name Print-Services
```

---

### Adım 2: Gerekli Yönetim Araçlarının Eklenmesi

Rol seçildikten sonra sistem otomatik olarak gerekli yönetim araçlarını kurmak için onay penceresi açar.

![Add Features Dialog](Images/3.png)
*Resim 3: "Add features that are required for Print and Document Services?" onay penceresi. Remote Server Administration Tools, Role Administration Tools ve Print and Document Services Tools bileşenleri listelenmekte.*

**Yüklenen Bileşenler:**
- **Remote Server Administration Tools:** Uzaktan yönetim araçları
- **Role Administration Tools:** Rol yönetim araçları
- **[Tools] Print and Document Services Tools:** Yazıcı yönetim konsolu

**Teknik Özellikler:**
- Print Management Console (printmanagement.msc)
- Print PowerShell Module
- RSAT araçları

✅ **Include management tools (if applicable)** seçeneği işaretli olduğundan emin olun ve **Add Features** butonuna tıklayın.

**PowerShell ile Yönetim Araçları Yükleme:**

```powershell
# Yönetim araçlarını dahil ederek kurulum
Install-WindowsFeature -Name Print-Services -IncludeManagementTools

# Print yönetim modülünü import etme
Import-Module PrintManagement

# Kullanılabilir cmdlet'leri listele
Get-Command -Module PrintManagement
```

---

### Adım 3: Print and Document Services Bilgilendirme

**Print and Document Services** hakkında teknik bilgiler ve önemli notlar ekranı görüntülenir.

![Print and Document Services Info](Images/4.png)
*Resim 4: Print and Document Services bilgilendirme ekranı. Windows Server 2025 yazıcı sürücü desteği (Type 3 ve Type 4) ve güvenlik gereksinimleri açıklanmakta.*

**Things to Note:**

**📌 Windows Server 2025 Yazıcı Sürücüleri:**
- Windows Server 2025, **Type 3** veya **Type 4** yazıcı sürücülerini destekler
- Microsoft, **Type 4** yazıcı sürücülerinin kullanılmasını önerir
- Type 4 sürücüler kullanıldığında, domain üyesi olmayan 32-bit istemciler yazıcıya bağlanabilir (32-bit sürücü olmadan)

**🔒 Güvenlik Gereksinimleri:**
- İmzalı, **package aware** sürücüler kullanılmalıdır
- İmzasız veya package aware olmayan sürücüler kullanılacaksa:
  - İstemciler local administrator olmalı
  - **VEYA** "Computer\Administrative Templates\Printers\Point and Print Restrictions" group policy ile yapılandırılmalıdır

**📝 Type 3 vs Type 4 Sürücüler:**

| Özellik | Type 3 (v3) | Type 4 (v4) |
|---------|-------------|-------------|
| Mimari | Kernel-mode | User-mode |
| 32-bit Desteği | Zorunlu | Opsiyonel |
| Güvenlik | Düşük | Yüksek |
| Kararlılık | Orta | Yüksek |
| Windows 10/11 | Desteklenir | Önerilen |

**Learn more about the Printer Server Role** linkine tıklayarak detaylı bilgi alınabilir.

**Next** butonuna tıklayarak devam edilir.

---

### Adım 4: Role Services Seçimi

**Select role services to install for Print and Document Services** ekranında yüklenecek servisler seçilir.

![Select Role Services](Images/5.png)
*Resim 5: Print and Document Services role services seçim ekranı. Print Server, Internet Printing ve LPD Service seçenekleri görülmekte.*

**Seçilen Role Services:**

- ✅ **Print Server**
  - Line Printer Daemon (LPD) Service
  - Merkezi yazıcı yönetimi ve paylaşım servisi
  - Temel print server fonksiyonları

- ✅ **Internet Printing**
  - UNIX tabanlı bilgisayarlar için yazıcı servisi
  - HTTP/HTTPS üzerinden yazdırma desteği
  - IPP (Internet Printing Protocol) desteği

- ✅ **LPD Service**
  - Line Printer Remote (LPR) servisi
  - UNIX/Linux sistemlerle uyumluluk
  - TCP/IP üzerinden yazdırma

**Otomatik Eklenen Bağımlılıklar:**

**Web Server Role (IIS)** ve **Role Services** ekranında Web Server seçenekleri de otomatik eklenir.

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

---

### Adım 5: Kurulum Onayı

**Confirm installation selections** ekranında kurulacak bileşenler listelenir.

![Confirm Installation](Images/6.png)
*Resim 6: Kurulum onay ekranı. .NET Framework 4.8, ASP.NET 4.8, Print and Document Services bileşenleri, Remote Server Administration Tools, ve Web Server (IIS) kurulacak öğeler listesinde.*

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
└── (Required components)
```

**Kurulum Seçenekleri:**

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

Kurulum tamamlandıktan sonra **Close** butonu ile wizard kapatılır.

---

## 🖥️ Print Management Konsolu

### Adım 6: Print Management'ı Açma

Kurulum tamamlandıktan sonra **Windows Tools** menüsünden **Print Management** konsolu açılır.

![Windows Tools - Print Management](Images/7.png)
*Resim 7: Windows araması ile "Print Management" aranması ve sonuçlarda Print Management (System) uygulamasının görünümü. Ayrıca Windows Tools klasöründe diğer yönetim araçları da listelenmekte.*

**Erişim Yolları:**

1. **Start Menu → Search "Print Management"**
2. **Start → Windows Tools → Print Management**
3. **Start → Run → printmanagement.msc**
4. **Server Manager → Tools → Print Management**
5. **PowerShell:** `printmanagement.msc`

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

---

### Adım 7: Print Management Console Arayüzü

Print Management konsolu açıldığında sol panelde yazıcı yönetim yapısı görüntülenir.

![Print Management Console](Images/8.png)
*Resim 8: Print Management konsolu ana ekranı. Sol panelde Custom Filters, All Printers, All Drivers, Print Servers yapısı, sağ panelde Microsoft Print to PDF yazıcısının detaylı bilgileri (Queue Status: Ready, Driver Version: 10.0.26100.4484, Driver Type: Type 4 - User Mode) gösterilmekte.*

**Konsol Yapısı:**

```
Print Management
├── Custom Filters
│   ├── All Printers (1)
│   ├── All Drivers (6)
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

**Konsol Özellikleri:**

- **Custom Filters:** Özel yazıcı filtreleri oluşturma
- **Print Servers:** Merkezi yazıcı sunucuları yönetimi
- **Deployed Printers:** GPO ile dağıtılan yazıcılar
- **Forms:** Kağıt boyutları ve form tanımları

**Yazıcı Durumları:**

| Status | Anlamı | Aksiyon |
|--------|--------|---------|
| Ready | Hazır | Normal çalışma |
| Offline | Çevrimdışı | Bağlantı kontrolü |
| Paused | Duraklatılmış | Manuel müdahale |
| Error | Hata | Troubleshooting gerekli |

---

## 🌐 Ağ Yazıcısı Ekleme

### Adım 8: Add Printer Wizard Başlatma

Print Management konsolunda **Printers** klasörüne sağ tıklanır.

![Add Printer Menu](Images/9.png)
*Resim 9: Print Management konsolunda Printers klasörüne sağ tık menüsü. "Add Printer...", "Show Extended View", "Refresh", "Export List", "View", "Arrange Icons", "Help" seçenekleri görülmekte.*

**Sağ Tık Menü Seçenekleri:**

- **Add Printer...** - Yeni yazıcı ekleme ✅
- **Show Extended View** - Genişletilmiş görünüm
- **Refresh** - Listeyi yenileme
- **Export List...** - Yazıcı listesi dışa aktarma
- **View** - Görünüm seçenekleri
- **Arrange Icons** - İkon düzenleme
- **Line up Icons** - İkonları hizalama
- **Help** - Yardım menüsü

**Add Printer...** seçeneğine tıklayın.

**PowerShell ile Yazıcı Ekleme Alternatifi:**

```powershell
# TCP/IP yazıcı portu oluşturma
Add-PrinterPort -Name "IP_192.168.31.201" -PrinterHostAddress "192.168.31.201" -PortNumber 9100

# Yazıcı sürücüsü yükleme
Add-PrinterDriver -Name "Microsoft XPS Document Writer v4"

# Yazıcı ekleme
Add-Printer -Name "Network Printer" -DriverName "Microsoft XPS Document Writer v4" -PortName "IP_192.168.31.201"
```

---

### Adım 9: Yazıcı Kurulum Yöntemi Seçimi

**Network Printer Installation Wizard** açılır ve kurulum yöntemi seçimi yapılır.

![Printer Installation Method](Images/10.png)
*Resim 10: "Network Printer Installation Wizard" - Printer Installation ekranı. Dört kurulum yöntemi listelenmekte: "Search the network for printers", "Add an IPP, TCP/IP, or Web Services Printer by IP address or hostname" (seçili), "Add a new printer using an existing port", "Create a new port and add a new printer".*

**Kurulum Yöntemleri:**

1. ⚪ **Search the network for printers**
   - Ağ taraması ile otomatik yazıcı keşfi
   - WSD ve Bonjour protokolleri desteği

2. 🔵 **Add an IPP, TCP/IP, or Web Services Printer by IP address or hostname** ✅
   - Manuel IP adresi girişi (Önerilen)
   - IPP, RAW, LPR protokol desteği
   - DNS hostname veya IP kullanımı

3. ⚪ **Add a new printer using an existing port**
   - Mevcut port üzerinden yazıcı ekleme
   - LPT1: (Printer Port) seçeneği

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

**🔵 Add an IPP, TCP/IP, or Web Services Printer** seçeneğini işaretleyin ve **Next** butonuna tıklayın.

**PowerShell Port Yönetimi:**

```powershell
# Mevcut portları listeleme
Get-PrinterPort | Select-Object Name, Description, PortMonitor

# TCP/IP port oluşturma
Add-PrinterPort -Name "IP_192.168.31.201" -PrinterHostAddress "192.168.31.201"

# LPR port oluşturma
Add-PrinterPort -Name "LPR_192.168.31.201" -LprHostAddress "192.168.31.201" -LprQueue "PASSTHRU"
```

---

### Adım 10: Yazıcı IP Adresi Yapılandırması

**Printer Address** ekranında yazıcının ağ bilgileri girilir.

![Printer Address Configuration](Images/11.png)
*Resim 11: Printer Address yapılandırma ekranı. Type of Device: "TCP/IP Device", Host name or IP address: "192.168.31.201", Port name: "192.168.31.201", "Auto detect the printer driver to use" checkbox'ı işaretli. Altta "Autodetect detects WSD and TCP/IP printers" bilgisi.*

**Yapılandırma Parametreleri:**

**Type of Device:** `TCP/IP Device`

**Cihaz Türü Seçenekleri:**
- **TCP/IP Device** - Standart ağ yazıcıları (RAW/LPR) ✅
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
- IPP yazıcı aramak için **Type of Device** dropdown'ından **IPP** seçilmelidir

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

---

### Adım 11: Yazıcı Sürücüsü Seçimi

Autodetect çalıştıktan sonra **Printer Driver** seçim ekranı açılır.

![Printer Driver Selection](Images/12.png)
*Resim 12: Printer Driver seçim ekranı. Üç seçenek sunulmakta: "Use the printer driver that the wizard selected" (Compatible driver cannot be found.), "Use an existing printer driver on the computer" (Microsoft IPP Class Driver), "Install a new driver" (seçili).*

**Sürücü Seçim Yöntemleri:**

1. ⚪ **Use the printer driver that the wizard selected**
   - Autodetect ile bulunan sürücü (Önerilen)
   - *Compatible driver cannot be found.* - Bu örnekte algılanmadı

2. ⚪ **Use an existing printer driver on the computer**
   - Sistemde yüklü sürücüler kullanılır
   - Dropdown listeden seçim yapılır
   - Örnek: `Microsoft IPP Class Driver`

3. 🔵 **Install a new driver** ✅
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

**🔵 Install a new driver** seçeneğini işaretleyin ve **Next** butonuna tıklayın.

**PowerShell ile Sürücü Yönetimi:**

```powershell
# Yüklü sürücüleri listeleme
Get-PrinterDriver | Select-Object Name, PrinterEnvironment, DriverVersion

# Sürücü bilgisi detaylı
Get-PrinterDriver -Name "Microsoft XPS Document Writer v4" | Format-List *

# Sürücü yükleme (INF dosyasından)
Add-PrinterDriver -Name "HP LaserJet P3015" -InfPath "C:\Drivers\HP\hpbx3w81.inf"
```

---

### Adım 12: Yazıcı Üreticisi ve Model Seçimi

**Printer Installation** ekranında yazıcı üreticisi ve modeli seçilir.

![Manufacturer and Model Selection](Images/13.png)
*Resim 13: Printer Installation - "Select the manufacturer and model of your printer" ekranı. Sol tarafta Manufacturer listesi (Generic, Microsoft seçili), sağ tarafta Printers listesi (Microsoft MS-XPS Class Driver 2, Microsoft OpenXPS Class Driver, Microsoft OpenXPS Class Driver 2, Microsoft PCL6 Class Driver, Microsoft PS Class Driver). Alt kısımda "This driver is digitally signed" mesajı, Windows Update ve Have Disk butonları.*

**Sürücü Seçim Ekranı:**

**Manufacturer (Üretici) Listesi:**
- Generic
- 🔵 **Microsoft** ✅
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

---

### Adım 13: Yazıcı Adı ve Paylaşım Ayarları

**Printer Name and Sharing Settings** ekranında yazıcı tanımlanır ve paylaşım yapılandırması yapılır.

![Printer Name and Sharing Settings](Images/14.png)
*Resim 14: Printer Name and Sharing Settings ekranı. Printer Name: "Microsoft MS-XPS Class Driver 2", "Share this printer" checkbox'ı işaretli, Share Name: "Microsoft MS-XPS Class Driver 2", Location ve Comment alanları boş.*

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

---

### Adım 14: Kurulum Tamamlanması

**Completing the Network Printer Installation Wizard** ekranında kurulum sonucu görüntülenir.

![Installation Complete](Images/1.png)
*Resim 1: "Completing the Network Printer Installation Wizard" ekranı. Status kısmında "Driver installation succeeded." ve "Printer installation succeeded." başarı mesajları, "Your printer has been installed successfully." onay mesajı. Alt kısımda "Print test page" ve "Add another printer" checkbox seçenekleri, Finish butonu.*

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
- **Önerilir:** Test yazdırma için işaretleyin

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

# Test sayfası yazdırma (PowerShell ile)
$printer = Get-Printer -Name "Microsoft MS-XPS Class Driver 2"
Invoke-Command -ScriptBlock {
    $printer | Out-Printer
}

# Print Management'ta görüntüleme
Get-Printer | Where-Object {$_.ComputerName -eq $env:COMPUTERNAME}
```

**Event Log Kontrolü:**

```powershell
# Yazıcı kurulum event'lerini görüntüleme
Get-EventLog -LogName System -Source "Print" -Newest 10

# Microsoft-Windows-PrintService event log
Get-WinEvent -LogName "Microsoft-Windows-PrintService/Admin" -MaxEvents 20 | 
    Format-Table TimeCreated, Id, Message -AutoSize
```

**Test Sayfası Yazdırma:**

```powershell
# Manuel test sayfası yazdırma
function Print-TestPage {
    param([string]$PrinterName)
    
    $TestContent = @"
========================================
PRINT TEST PAGE
========================================
Printer: $PrinterName
Date/Time: $(Get-Date)
Server: $env:COMPUTERNAME
User: $env:USERNAME
========================================
Test completed successfully!
========================================
"@
    
    $TestFile = "$env:TEMP\testpage_$(Get-Date -Format 'yyyyMMddHHmmss').txt"
    $TestContent | Out-File -FilePath $TestFile -Encoding UTF8
    
    Start-Process -FilePath "notepad.exe" -ArgumentList "/p $TestFile" -Wait
    Start-Sleep -Seconds 2
    Remove-Item -Path $TestFile -Force -ErrorAction SilentlyContinue
}

# Kullanım
Print-TestPage -PrinterName "Microsoft MS-XPS Class Driver 2"
```

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

# Belirli bir işi duraklat
Suspend-PrintJob -PrinterName "Microsoft MS-XPS Class Driver 2" -ID 1

# İşi devam ettir
Resume-PrintJob -PrinterName "Microsoft MS-XPS Class Driver 2" -ID 1

# Yazıcıyı duraklatma/devam ettirme
Set-Printer -Name "Microsoft MS-XPS Class Driver 2" -PrinterStatus Paused
Set-Printer -Name "Microsoft MS-XPS Class Driver 2" -PrinterStatus Normal
```

### Kullanıcı İzinleri

**İzin Seviyeleri:**

| İzin | Print | Manage Printer | Manage Documents |
|------|-------|----------------|------------------|
| **Print** | ✅ | ❌ | ❌ |
| **Manage this printer** | ✅ | ✅ | ❌ |
| **Manage documents** | ✅ | ❌ | ✅ |
| **Full Control** | ✅ | ✅ | ✅ |

**PowerShell İzin Yönetimi:**

```powershell
# Domain Users'a print izni verme
$printer = Get-Printer -Name "Microsoft MS-XPS Class Driver 2"
$acl = Get-Acl -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Printers\$($printer.Name)"

# Grup bazlı izin ekleme
$permission = "DOMAIN\IT-Team","FullControl","Allow"
$accessRule = New-Object System.Security.AccessControl.RegistryAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Printers\$($printer.Name)" -AclObject $acl

# Yazıcı güvenlik descriptorü ile izin yönetimi
$sd = Get-PrinterSecurityDescriptor -PrinterName "Microsoft MS-XPS Class Driver 2"
# SDDL formatında düzenleme yapılabilir
```

### Yazdırma İşi İzleme

**Monitoring ve Raporlama:**

```powershell
# Gerçek zamanlı izleme scripti
while ($true) {
    Clear-Host
    $jobs = Get-PrintJob -PrinterName "Microsoft MS-XPS Class Driver 2"
    Write-Host "=== Print Job Monitor ===" -ForegroundColor Cyan
    Write-Host "Active Jobs: $($jobs.Count)" -ForegroundColor Green
    Write-Host "Time: $(Get-Date)" -ForegroundColor Yellow
    Write-Host ""
    
    if ($jobs.Count -gt 0) {
        $jobs | Format-Table JobName, UserName, @{N='Size(KB)';E={[math]::Round($_.Size/1KB,2)}}, JobStatus, SubmittedTime -AutoSize
    } else {
        Write-Host "No active print jobs" -ForegroundColor Gray
    }
    
    Start-Sleep -Seconds 5
}

# Günlük yazdırma raporu
$StartDate = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PrintService/Operational'
    StartTime = $StartDate
    ID = 307  # Print Job Completed event
} | Select-Object TimeCreated, @{N='User';E={$_.Properties[3].Value}}, @{N='Document';E={$_.Properties[4].Value}}, @{N='Pages';E={$_.Properties[7].Value}} |
Export-Csv -Path "C:\Reports\PrintLog_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
```

### Domain Üzerinden Dağıtım (Deploy)

**Group Policy ile Yazıcı Dağıtımı:**

```powershell
# Print Management konsolundan GPO ile dağıtım
# GUI Adımları:
# 1. Print Management Console'da yazıcıya sağ tık
# 2. "Deploy with Group Policy..." seçeneğini seç
# 3. GPO seç veya oluştur
# 4. Per User veya Per Computer seç
# 5. Add ve Apply

# PowerShell ile GPO printer deployment
New-GPO -Name "Deployed Printers - Finance" -Comment "Finance department printers"

# Yazıcıyı GPO'ya bağlama (requires Print Management module)
$GPOName = "Deployed Printers - Finance"
$PrinterPath = "\\DOMAIN\Microsoft MS-XPS Class Driver 2"

# Registry bazlı deployment
Set-GPRegistryValue -Name $GPOName `
    -Key "HKCU\Software\Microsoft\Windows NT\CurrentVersion\PrinterPorts" `
    -ValueName $PrinterPath `
    -Type String `
    -Value "winspool,Ne00:"

# GPO'yu OU'ya bağlama
New-GPLink -Name $GPOName -Target "OU=Finance,OU=Departments,DC=domain,DC=local" -LinkEnabled Yes
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
        # Bağlantıyı ekle
        (New-Object -ComObject WScript.Network).AddWindowsPrinterConnection($Printer)
        Write-Host "✅ Eklendi: $Printer" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Hata: $Printer - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Varsayılan yazıcı ayarlama
(New-Object -ComObject WScript.Network).SetDefaultPrinter("\\DOMAIN\Microsoft MS-XPS Class Driver 2")
```

**Login Script ile Otomatik Bağlama:**

```powershell
# Login script (\\domain\netlogon\printer-map.ps1)
<#
.SYNOPSIS
    Kullanıcı login'de otomatik yazıcı bağlama
.DESCRIPTION
    Departman bazlı yazıcı mapping scripti
#>

# Kullanıcının departmanını al
$UserDept = ([ADSISEARCHER]"samaccountname=$($env:USERNAME)").FindOne().Properties.department

# Departman bazlı yazıcı mapping
switch ($UserDept) {
    "Finance" {
        $Printers = @("\\DOMAIN\Finance-Printer", "\\DOMAIN\Microsoft MS-XPS Class Driver 2")
        $DefaultPrinter = "\\DOMAIN\Finance-Printer"
    }
    "IT" {
        $Printers = @("\\DOMAIN\IT-ColorPrinter", "\\DOMAIN\IT-BWPrinter")
        $DefaultPrinter = "\\DOMAIN\IT-ColorPrinter"
    }
    default {
        $Printers = @("\\DOMAIN\Microsoft MS-XPS Class Driver 2")
        $DefaultPrinter = "\\DOMAIN\Microsoft MS-XPS Class Driver 2"
    }
}

# Yazıcıları ekle
$Network = New-Object -ComObject WScript.Network
foreach ($Printer in $Printers) {
    try {
        $Network.AddWindowsPrinterConnection($Printer)
    } catch {
        # Sessizce devam et
    }
}

# Varsayılan yazıcıyı ayarla
try {
    $Network.SetDefaultPrinter($DefaultPrinter)
} catch {
    # Sessizce devam et
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
.AUTHOR
    Serif SELEN
.VERSION
    1.0
#>

# Elevation kontrolü
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Bu script yönetici yetkileriyle çalıştırılmalıdır!"
    Break
}

# Print Services rolünü kurma
Write-Host "`n=== Print Services Rol Kurulumu ===" -ForegroundColor Cyan
Write-Host "Print Services rolü kuruluyor..." -ForegroundColor Yellow

$Features = @('Print-Services', 'Print-Internet', 'Print-LPD-Service')
$InstallResult = Install-WindowsFeature -Name $Features -IncludeManagementTools -ErrorAction Stop

if ($InstallResult.Success) {
    Write-Host "✅ Print Services başarıyla kuruldu!" -ForegroundColor Green
} else {
    Write-Host "❌ Kurulum başarısız!" -ForegroundColor Red
    exit 1
}

# Print Management modülünü içe aktarma
Import-Module PrintManagement -ErrorAction Stop

# Yazıcı yapılandırması
$PrinterConfig = @{
    Name = "Microsoft MS-XPS Class Driver 2"
    DriverName = "Microsoft XPS Document Writer v4"
    IPAddress = "192.168.31.201"
    PortName = "IP_192.168.31.201"
    ShareName = "MS-XPS-NET"
    Location = "Building A, Floor 2, Network Printer"
    Comment = "Network XPS Printer - Centrally Managed"
    Published = $true
}

Write-Host "`n=== Yazıcı Yapılandırması ===" -ForegroundColor Cyan

# TCP/IP Port oluşturma
Write-Host "Yazıcı portu oluşturuluyor: $($PrinterConfig.PortName)" -ForegroundColor Yellow
try {
    Add-PrinterPort -Name $PrinterConfig.PortName `
        -PrinterHostAddress $PrinterConfig.IPAddress `
        -PortNumber 9100 `
        -SNMP $true `
        -SNMPCommunity "public" `
        -ErrorAction Stop
    Write-Host "✅ Port oluşturuldu" -ForegroundColor Green
} catch {
    Write-Host "⚠️ Port zaten mevcut veya oluşturulamadı: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Sürücü kontrolü ve yükleme
Write-Host "Yazıcı sürücüsü kontrol ediliyor..." -ForegroundColor Yellow
$Driver = Get-PrinterDriver -Name $PrinterConfig.DriverName -ErrorAction SilentlyContinue

if (-not $Driver) {
    Write-Host "Sürücü yükleniyor: $($PrinterConfig.DriverName)" -ForegroundColor Yellow
    try {
        Add-PrinterDriver -Name $PrinterConfig.DriverName -ErrorAction Stop
        Write-Host "✅ Sürücü yüklendi" -ForegroundColor Green
    } catch {
        Write-Host "❌ Sürücü yüklenemedi: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "✅ Sürücü zaten mevcut" -ForegroundColor Green
}

# Yazıcı ekleme
Write-Host "Yazıcı ekleniyor: $($PrinterConfig.Name)" -ForegroundColor Yellow
try {
    Add-Printer -Name $PrinterConfig.Name `
        -DriverName $PrinterConfig.DriverName `
        -PortName $PrinterConfig.PortName `
        -Shared $true `
        -ShareName $PrinterConfig.ShareName `
        -Location $PrinterConfig.Location `
        -Comment $PrinterConfig.Comment `
        -Published $PrinterConfig.Published `
        -ErrorAction Stop
    
    Write-Host "✅ Yazıcı başarıyla eklendi!" -ForegroundColor Green
} catch {
    Write-Host "❌ Yazıcı eklenemedi: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Yazıcı durumunu kontrol etme ve raporlama
Write-Host "`n=== Kurulum Raporu ===" -ForegroundColor Cyan
$Printer = Get-Printer -Name $PrinterConfig.Name -ErrorAction SilentlyContinue

if ($Printer) {
    Write-Host "Yazıcı Bilgileri:" -ForegroundColor White
    $Printer | Format-List Name, DriverName, PortName, Shared, ShareName, Published, PrinterStatus | Out-String | Write-Host
    
    # UNC yolunu göster
    $UNCPath = "\\$env:COMPUTERNAME\$($Printer.ShareName)"
    Write-Host "UNC Yolu: $UNCPath" -ForegroundColor Green
    
    # Bağlantı testi
    Write-Host "`nYazıcı bağlantısı test ediliyor..." -ForegroundColor Yellow
    $TestConn = Test-NetConnection -ComputerName $PrinterConfig.IPAddress -Port 9100 -InformationLevel Quiet
    if ($TestConn) {
        Write-Host "✅ Yazıcıya bağlantı başarılı (Port 9100)" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Yazıcıya bağlantı kurulamadı!" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ Yazıcı bulunamadı!" -ForegroundColor Red
}

Write-Host "`n✅ Kurulum tamamlandı!" -ForegroundColor Green
Write-Host "`nYazıcı yönetimi için: printmanagement.msc" -ForegroundColor Cyan
```

### Toplu Yazıcı Ekleme (CSV'den)

```powershell
<#
.SYNOPSIS
    CSV dosyasından toplu yazıcı kurulumu
.DESCRIPTION
    CSV formatındaki yazıcı listesini okuyarak toplu kurulum yapar
#>

# CSV Format:
# Name,IPAddress,DriverName,Location,Department,ShareName,Comment

$CSVPath = "C:\Scripts\Printers.csv"

# Örnek CSV içeriği oluşturma
$SampleCSV = @"
Name,IPAddress,DriverName,Location,Department,ShareName,Comment
Finance-Printer,192.168.31.202,Microsoft XPS Document Writer v4,Building A - Floor 3,Finance,FIN-PRINT,Finance Department Printer
HR-Printer,192.168.31.203,Microsoft XPS Document Writer v4,Building B - Floor 1,HR,HR-PRINT,HR Department Printer
IT-ColorPrinter,192.168.31.204,Microsoft XPS Document Writer v4,Building A - Floor 1,IT,IT-COLOR,IT Color Printer
"@

# Örnek CSV'yi oluştur (ilk çalıştırmada)
if (-not (Test-Path $CSVPath)) {
    $SampleCSV | Out-File -FilePath $CSVPath -Encoding UTF8
    Write-Host "Örnek CSV dosyası oluşturuldu: $CSVPath" -ForegroundColor Yellow
    Write-Host "Lütfen dosyayı düzenleyin ve scripti tekrar çalıştırın." -ForegroundColor Yellow
    exit
}

# CSV'den yazıcı listesini oku
$Printers = Import-Csv -Path $CSVPath

Write-Host "=== Toplu Yazıcı Kurulumu ===" -ForegroundColor Cyan
Write-Host "Toplam $($Printers.Count) yazıcı kurulacak`n" -ForegroundColor Yellow

foreach ($Printer in $Printers) {
    Write-Host "İşleniyor: $($Printer.Name)" -ForegroundColor White
    
    $PortName = "IP_$($Printer.IPAddress)"
    
    # Port oluştur
    try {
        Add-PrinterPort -Name $PortName -PrinterHostAddress $Printer.IPAddress -ErrorAction Stop
        Write-Host "  ✅ Port oluşturuldu: $PortName" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠️ Port zaten mevcut: $PortName" -ForegroundColor Yellow
    }
    
    # Yazıcı ekle
    try {
        Add-Printer -Name $Printer.Name `
            -DriverName $Printer.DriverName `
            -PortName $PortName `
            -Shared $true `
            -ShareName $Printer.ShareName `
            -Location $Printer.Location `
            -Comment $Printer.Comment `
            -ErrorAction Stop
        
        Write-Host "  ✅ $($Printer.Name) eklendi`n" -ForegroundColor Green
    } catch {
        Write-Host "  ❌ Hata: $($_.Exception.Message)`n" -ForegroundColor Red
    }
}

Write-Host "`n✅ Toplu kurulum tamamlandı!" -ForegroundColor Green

# Özet rapor
$InstalledPrinters = Get-Printer | Where-Object {$_.Name -in $Printers.Name}
Write-Host "`nKurulu Yazıcı Sayısı: $($InstalledPrinters.Count)" -ForegroundColor Cyan
$InstalledPrinters | Format-Table Name, DriverName, PortName, Shared -AutoSize
```

### Yazıcı Sağlık Kontrolü ve Monitoring

```powershell
<#
.SYNOPSIS
    Yazıcı sağlık kontrolü ve durum raporu
.DESCRIPTION
    Tüm yazıcılar için detaylı sağlık kontrolü yapar
#>

function Test-PrinterHealth {
    [CmdletBinding()]
    param()
    
    Write-Host "=== Yazıcı Sağlık Kontrolü ===" -ForegroundColor Cyan
    Write-Host "Tarih: $(Get-Date)`n" -ForegroundColor Yellow
    
    $Printers = Get-Printer
    $Report = @()
    
    foreach ($Printer in $Printers) {
        Write-Host "Kontrol ediliyor: $($Printer.Name)" -ForegroundColor White
        
        $Status = [PSCustomObject]@{
            Name = $Printer.Name
            Status = $Printer.PrinterStatus
            JobCount = 0
            Shared = $Printer.Shared
            Published = $Printer.Published
            DriverVersion = ""
            Connectivity = "N/A"
            LastError = "None"
        }
        
        # İş sayısı
        try {
            $Jobs = Get-PrintJob -PrinterName $Printer.Name -ErrorAction Stop
            $Status.JobCount = $Jobs.Count
        } catch {
            $Status.LastError = "Cannot get job count"
        }
        
        # Sürücü versiyonu
        try {
            $Driver = Get-PrinterDriver -Name $Printer.DriverName -ErrorAction Stop
            $Status.DriverVersion = $Driver.DriverVersion
        } catch {
            $Status.DriverVersion = "Unknown"
        }
        
        # Port connectivity testi
        if ($Printer.PortName -match "IP_(.+)") {
            $IP = $Matches[1]
            Write-Host "  Bağlantı test ediliyor: $IP" -ForegroundColor Gray
            $TestResult = Test-NetConnection -ComputerName $IP -Port 9100 -InformationLevel Quiet -WarningAction SilentlyContinue
            $Status.Connectivity = if ($TestResult) { "✅ Online" } else { "❌ Offline" }
        }
        
        $Report += $Status
        Write-Host "  Durum: $($Status.Status) | Bağlantı: $($Status.Connectivity)`n" -ForegroundColor $(if ($Status.Status -eq 'Normal') { 'Green' } else { 'Yellow' })
    }
    
    # Özet rapor
    Write-Host "`n=== Özet Rapor ===" -ForegroundColor Cyan
    $Report | Format-Table Name, Status, JobCount, Connectivity, Shared, Published -AutoSize
    
    # CSV'ye kaydet
    $ReportPath = "C:\Reports\PrinterHealth_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $ReportDir = Split-Path -Path $ReportPath -Parent
    if (-not (Test-Path $ReportDir)) {
        New-Item -Path $ReportDir -ItemType Directory -Force | Out-Null
    }
    $Report | Export-Csv -Path $ReportPath -NoTypeInformation
    Write-Host "`n✅ Rapor kaydedildi: $ReportPath" -ForegroundColor Green
    
    return $Report
}



```powershell
<#
.SYNOPSIS
    Yazıcı yapılandırması yedekleme ve geri yükleme
.DESCRIPTION
    Tüm yazıcı, port ve sürücü yapılandırmalarını yedekler
#>

function Backup-PrinterConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$BackupPath = "C:\PrinterBackup"
    )
    
    Write-Host "=== Yazıcı Yapılandırması Yedekleme ===" -ForegroundColor Cyan
    
    # Yedek klasörü oluştur
    $BackupFolder = Join-Path -Path $BackupPath -ChildPath (Get-Date -Format 'yyyyMMdd_HHmmss')
    if (-not (Test-Path $BackupFolder)) {
        New-Item -Path $BackupFolder -ItemType Directory -Force | Out-Null
    }
    
    Write-Host "Yedekleme konumu: $BackupFolder`n" -ForegroundColor Yellow
    
    # Yazıcıları dışa aktarma
    Write-Host "Yazıcılar yedekleniyor..." -ForegroundColor White
    $Printers = Get-Printer
    $Printers | Export-Clixml -Path (Join-Path -Path $BackupFolder -ChildPath "Printers.xml")
    Write-Host "  ✅ $($Printers.Count) yazıcı yedeklendi" -ForegroundColor Green
    
    # Portları dışa aktarma
    Write-Host "Portlar yedekleniyor..." -ForegroundColor White
    $Ports = Get-PrinterPort
    $Ports | Export-Clixml -Path (Join-Path -Path $BackupFolder -ChildPath "PrinterPorts.xml")
    Write-Host "  ✅ $($Ports.Count) port yedeklendi" -
```
## 📄 Doküman Bilgileri

| Özellik | Değer |
|---------|-------|
| **Yazar** | Serif SELEN |
| **Tarih** | 4 Kasım 2025 |
| **Versiyon** | 1.0 |
| **Platform** | VMware Workstation Pro 17 |
| **İşletim Sistemi** | Windows Server 2019/2022/2025 |
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

---

**Not:** Bu doküman, Windows Server 2019, 2022 ve 2025 sürümleri için geçerlidir. Önceki Windows Server sürümlerinde bazı adımlar farklılık gösterebilir.
