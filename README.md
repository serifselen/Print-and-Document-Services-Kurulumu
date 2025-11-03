# Windows Server 2025 - Yazıcı ve Belge Hizmetleri Kurulum Rehberi

## 🎯 Genel Bakış

Bu rehber, Windows Server 2025 işletim sistemi üzerinde **Print and Document Services** rolünün kurulumunu ve ağ yazıcısı yapılandırmasını adım adım açıklamaktadır. Bu kurulum ile merkezi yazıcı yönetimi sağlayabilir, ağ yazıcılarını yönetebilir ve çoklu platform yazdırma desteği sunabilirsiniz.

**Önemli Not:** Bu kurulumdan önce Active Directory ve DNS yapılandırmasının tamamlanmış olması gerekmektedir.

---

## 📋 İçindekiler

- [Ön Gereksinimler ve Hazırlık](#ön-gereksinimler-ve-hazırlık)
- [Print and Document Services Kurulum Adımları](#-print-and-document-services-kurulum-adımları)
  - [Adım 1: Server Manager Ana Ekranı](#adım-1-server-manager-ana-ekranı)
  - [Adım 2: "Add Roles and Features Wizard" Başlatma](#adım-2-add-roles-and-features-wizard-başlatma)
  - [Adım 3: Kurulum Türü Seçimi](#adım-3-kurulum-türü-seçimi)
  - [Adım 4: Hedef Sunucu Seçimi](#adım-4-hedef-sunucu-seçimi)
  - [Adım 5: Print and Document Services Rol Seçimi](#adım-5-print-and-document-services-rol-seçimi)
  - [Adım 6: Rol Hizmetlerinin Seçimi](#adım-6-rol-hizmetlerinin-seçimi)
  - [Adım 7: Kurulum Öncesi Bilgilendirme Ekranı](#adım-7-kurulum-öncesi-bilgilendirme-ekranı)
  - [Adım 8: Kurulum Onayı ve Başlatma](#adım-8-kurulum-onayı-ve-başlatma)
- [Print Management Konsolu](#-print-management-konsolu)
  - [Adım 9: Print Management Konsoluna Erişim](#adım-9-print-management-konsoluna-erişim)
  - [Adım 10: Yazıcı Ekleme Menüsü](#adım-10-yazıcı-ekleme-menüsü)
- [Ağ Yazıcısı Yapılandırması](#-ağ-yazıcısı-yapılandırması)
  - [Adım 11: Kurulum Yöntemi Seçimi](#adım-11-kurulum-yöntemi-seçimi)
  - [Adım 12: Yazıcı Ağ Ayarları](#adım-12-yazıcı-ağ-ayarları)
  - [Adım 13: Yazıcı Sürücüyü Seçimi](#adım-13-yazıcı-sürücüyü-seçimi)
  - [Adım 14: Yazıcı Adı ve Paylaşım Ayarları](#adım-14-yazıcı-adı-ve-paylaşım-ayarları)
  - [Adım 15: Kurulum Tamamlanması](#adım-15-kurulum-tamamlanması)
  - [Adım 16: Print Management'te Yazıcının Görünümü](#adım-16-print-managementte-yazıcının-görünümü)
- [Teknik Konfigürasyon](#-teknik-konfigürasyon)
- [Doğrulama ve Test](#-doğrulama-ve-test)
- [Doküman Bilgileri](#-doküman-bilgileri)

---

## 🔰 Ön Gereksinimler ve Hazırlık

### Sistem Gereksinimleri
| Bileşen | Minimum | Önerilen |
|---------|---------|-----------|
| **İşletim Sistemi** | Windows Server 2025 | Windows Server 2025 |
| **Bellek** | 2 GB RAM | 4 GB RAM veya üzeri |
| **Disk Alanı** | 10 GB boş alan | 20 GB boş alan |
| **İşlemci** | 1.4 GHz 64-bit | 2 GHz veya üzeri |

### Yazılım Gereksinimleri
- [x] .NET Framework 4.8
- [x] Web Server (IIS) rolü
- [x] Remote Server Administration Tools
- [x] Active Directory etki alanına katılım

### Ağ Gereksinimleri
- Statik IP adresi yapılandırılmış sunucu
- Etki alanına katılım (Serifselen.local)
- Ağ yazıcısı erişimi (192.168.31.201)

---

## 🖥️ Print and Document Services Kurulum Adımları

### Adım 1: Server Manager Ana Ekranı

![Adım 1](Images/1.png)

**Açıklama:**  
Server Manager açıldığında ana ekranda **"QUICK START"** bölümü görünür. Sol panelde sistem durumu bilgileri, sağ panelde ise hızlı yapılandırma seçenekleri yer alır.

**Ekran Görüntüsü Detayları:**
- **Dashboard** başlıklı ana ekran
- **QUICK START** bölümünde 3 seçenek:
  - Configure this local server
  - Add roles and features 
  - Add other servers to manage
- Sunucu adı: **Serifselen-WIN-SRV**
- IP Adresi: **192.168.31.100**

✅ Print and Document Services kurulumuna başlamak için **"Add roles and features"** bağlantısına tıklayın.

---

### Adım 2: "Add Roles and Features Wizard" Başlatma

![Adım 2](Images/2.png)

**Açıklama:**  
**Before You Begin** ekranında, kurulum öncesi ön koşullar özetlenir. Bu ekran sadece bilgilendirme amaçlıdır ve sunucunun rol kurulumuna hazır olduğunu doğrular.

**Ekran Görüntüsü Detayları:**
- **Before You Begin** başlıklı ekran
- 3 ön koşul maddesi:
  - Use a strong password for the Administrator account
  - Configure a static IP address for this server
  - Apply all critical updates before adding roles and features
- **Next** butonu etkin durumda

➡️ **Next** butonuna tıklayarak devam edin.

---

### Adım 3: Kurulum Türü Seçimi

![Adım 3](Images/3.png)

**Açıklama:**  
**Installation Type** ekranında kurulum yöntemi seçilir. Windows Server'da roller ve özellikler iki farklı şekilde kurulabilir.

**Ekran Görüntüsü Detayları:**
- **Installation Type** başlıklı ekran
- 2 seçenek:
  - Role-based or feature-based installation (seçili)
  - Remote Desktop Services installation
- Alt kısımda her seçeneğin kısa açıklaması

✅ **"Role-based or feature-based installation"** seçeneğini işaretleyin.  
➡️ **Next** butonuna tıklayın.

---

### Adım 4: Hedef Sunucu Seçimi

![Adım 4](Images/4.png)

**Açıklama:**  
**Server Selection** ekranında, kurulum yapılacak sunucu seçilir. Bu örnekte yerel sunucu seçilmiştir.

**Ekran Görüntüsü Detayları:**
- **Server Pool** bölümünde sunucular listelenir
- Seçili sunucu bilgileri:
  - Name: **Serifselen-WIN-SRV**
  - IP Address: **192.168.31.100** 
  - Operating System: **Windows Server 2025 Standard Evaluation**
- **Selected** sütununda onay işareti görülmekte

✅ Kurulum yapılacak sunucu zaten seçili gelir. Doğru sunucuyu seçtiğinizden emin olduktan sonra  
➡️ **Next** butonuna tıklayın.

---

### Adım 5: Print and Document Services Rol Seçimi

![Adım 5](Images/5.png)

**Açıklama:**  
**Server Roles** listesinden **"Print and Document Services"** rolü seçilir. Bu rol seçildiğinde otomatik olarak gerekli bağımlılıklar ve yönetim araçları önerilir.

**Ekran Görüntüsü Detayleri:**
- **Roles** ağacında **Print and Document Services** seçeneği işaretli
- Sağ tarafta açıklama panelinde rolün detaylı açıklaması
- Alt kısımda **Add features that are required for Print and Document Services?** sorulu diyalog kutusu:
  - Remote Server Administration Tools
  - Role Administration Tools
  - Print and Document Services Tools

✅ **"Include management tools (if applicable)"** seçeneği otomatik işaretlenir.  
➡️ **Add Features** butonuna tıklayıp **Next** butonuna geçin.

---

### Adım 6: Rol Hizmetlerinin Seçimi

![Adım 6](Images/6.png)

**Açıklama:**  
**Role Services** ekranında, Print and Document Services için ek hizmetler seçilir. Bu hizmetler yazıcı sunucusunun farklı senaryolarda çalışmasını sağlar.

**Ekran Görüntüsü Detayları:**
- **Role Services** başlıklı ekran
- **Print and Document Services** altında üç seçenek:
  - [x] **Print Server** (seçili)
  - [x] **Internet Printing** (seçili)
  - [x] **LPD Service** (seçili)
- Her hizmetin yanında açıklama:
  - Print Server: Allows local and network-connected printers to be managed and shared
  - Internet Printing: Provides web-based access to printers
  - LPD Service: Provides support for UNIX/Linux clients

✅ Gerekli tüm hizmetleri seçtikten sonra **Next** butonuna tıklayın.

---

### Adım 7: Kurulum Öncesi Bilgilendirme Ekranı

![Adım 7](Images/7.png)

**Açıklama:**  
**Things to Note** ekranında, yazıcı sürücüleri ve sistem uyumluluğu hakkında önemli bilgiler verilir. Özellikle Type 3 ve Type 4 sürücü farkları vurgulanır.

**Ekran Görüntüsü Detayları:**
- **Print and Document Services** başlıklı ekran
- 3 önemli uyarı:
  1. "Windows Server 2025 supports both Type 3 and Type 4 printer drivers."
  2. "Microsoft recommends the use of Type 4 printer drivers."
  3. "When using Type 4 drivers, 32-bit clients that are not domain-joined can connect to the server."

✅ Bu ekran sadece bilgilendirme amaçlıdır. **Next** butonuna tıklayarak devam edin.

---

### Adım 8: Kurulum Onayı ve Başlatma

![Adım 8](Images/8.png)

**Açıklama:**  
**Confirm installation selections** ekranında, tüm kurulum ayarları özetlenir. Bu aşamada ek ayarlar yapılabileceği gibi kurulum doğrudan başlatılabilir.

**Ekran Görüntüsü Detayları:**
- **Installation Selection** başlıklı ekran
- **Features** bölümünde:
  - .NET Framework 4.8 Features
  - Web Server (IIS) (Internet Printing için otomatik eklendi)
  - Print and Document Services
- **Confirmation** bölümünde:
  - [ ] Restart the destination server automatically if required (seçili değil)
  - [x] Include management tools (if applicable) (seçili)
- **Install** butonu etkin durumda

✅ Kurulum özetini kontrol edin ve **Install** butonuna tıklayarak kurulumu başlatın.

---

## ⚙️ Print Management Konsolu

### Adım 9: Print Management Konsoluna Erişim

![Adım 9](Images/9.png)

**Açıklama:**  
Kurulum tamamlandıktan sonra, yazıcı yönetimini gerçekleştirebilmek için **Print Management** konsoluna erişilir. Bu araç, Windows araçları menüsünden açılır.

**Ekran Görüntüsü Detayları:**
- **Windows Tools** menüsünün tam ekran görüntüsü
- Menüde **Print Management** seçeneği vurgulanmış
- Diğer araçların listesi:
  - Computer Management
  - DNS
  - Event Viewer
  - iSCSI Initiator
  - Local Security Policy
- Menü konumu: **Start > Windows Tools > Print Management**

✅ Araç başarıyla açıldığında sol panelde farklı yönetilebilir bileşenler görülür.

---

### Adım 10: Yazıcı Ekleme Menüsü

![Adım 10](Images/10.png)

**Açıklama:**  
Print Management ekranında, yeni yazıcı eklemek için gerekli menü erişimi sağlanır. Bu ekranda mevcut yazıcılar ve sistemdeki diğer bileşenler listelenir.

**Ekran Görüntüsü Detayları:**
- **Print Management** ana ekranı
- Sol panelde hiyerarşik yapı:
  - Print Servers
    - Serifselen-WIN-SRV (local)
      - Printers (sağ tık menüsü açık)
- Sağ tık menüsünde seçenekler:
  - Add Printer...
  - Show Extended View
  - Refresh
  - View
  - Arrange Icons
- Sağ tık menüsünde **Add Printer...** seçeneği vurgulanmış

✅ Bu işlem, yeni yazıcı ekleme sihirbazını başlatır.

---

## 🌐 Ağ Yazıcısı Yapılandırması

### Adım 11: Kurulum Yöntemi Seçimi

![Adım 11](Images/11.png)

**Açıklama:**  
**Network Printer Installation Wizard** ekranında, yazıcının nasıl kurulacağı belirlenir. Farklı kurulum yöntemleri mevcuttur.

**Ekran Görüntüsü Detayları:**
- **Printer Installation** başlıklı ekran
- **Pick an installation method** başlığı altında 4 seçenek:
  - [ ] Search the network for printers
  - [x] **Add an IPP, TCP/IP, or Web Services Printer by IP address or hostname** (seçili)
  - [ ] Add a new printer using an existing port
  - [ ] Create a new port and add a new printer
- Seçili seçenek için açıklama:
  "Use this option to add a printer using a standard TCP/IP port, IPP, or Web Services protocol"

✅ **Next** butonuna tıklayarak devam edin.

---

### Adım 12: Yazıcı Ağ Ayarları

![Adım 12](Images/12.png)

**Açıklama:**  
**Printer Address** ekranında, ağ yazıcısının IP adresi ve diğer ağ parametreleri girilir. Bu adım, yazıcının fiziksel konumunun belirlenmesi için kritiktir.

**Ekran Görüntüsü Detayları:**
- **Printer Address** başlıklı ekran
- **Device type** dropdown menüsü: **TCP/IP Device** (seçili)
- **Host name or IP address**: **192.168.31.201** (girilmiş)
- **Port name**: **192.168.31.201** (otomatik doldurulmuş)
- **Additional settings** bölümünde:
  - [x] **Auto detect the printer driver to use** (seçili)
  - SNMPE Settings butonu
- Alt kısımda durum: **"Searching for printer..."**

✅ Yazıcı IP'nizi doğru girdiğinizden emin olun. **Next** butonuna tıklayın.

---

### Adım 13: Yazıcı Sürücüyü Seçimi

![Adım 13](Images/13.png)

**Açıklama:**  
**Printer Driver** ekranında, yazıcı için uygun sürücü seçilir. Sistem otomatik algılama sonucu bulduğu sürücüyü önerir.

**Ekran Görüntüsü Detayları:**
- **Printer Driver** başlıklı ekran
- 3 seçenek:
  - [ ] Use the printer driver that the wizard selected
  - [ ] Use an existing printer driver on the computer
  - [x] **Install a new driver** (seçili)
- **Select the manufacturer and model** başlığı altında:
  - Manufacturer: **Microsoft** (seçili)
  - Printers: **Microsoft MS-XPS Class Driver 2** (seçili)
- Alt kısımda dijital imza bilgisi:
  - [x] **This driver is digitally signed**
  - Tell me why driver signing is important bağlantısı

✅ **Microsoft MS-XPS Class Driver 2** sürücüsünü seçin.  
➡️ **Next** butonuna tıklayarak devam edin.

---

### Adım 14: Yazıcı Adı ve Paylaşım Ayarları

![Adım 14](Images/14.png)

**Açıklama:**  
**Printer Name and Sharing Settings** ekranında, yazıcının adı belirlenir ve ağ üzerinde paylaşımı yapılandırılır.

**Ekran Görüntüsü Detayları:**
- **Printer Name and Sharing Settings** başlıklı ekran
- **Printer name**: **Microsoft MS-XPS Class Driver 2** (otomatik doldurulmuş)
- **Sharing** bölümünde:
  - [x] **Share this printer** (seçili)
  - Share name: **Microsoft MS-XPS Class Driver 2** (otomatik doldurulmuş)
- **Location** (boş): Yazıcının fiziksel konumu
- **Comment** (boş): Yazıcı hakkında ek bilgi
- Önizleme kutusunda UNC yolu: **\\\\Serifselen-WIN-SRV\\Microsoft MS-XPS Class Driver 2**

✅ Paylaşım ayarlarını doğru yapılandırdıktan sonra **Next** butonuna tıklayın.

---

### Adım 15: Kurulum Tamamlanması

![Adım 15](Images/15.png)

**Açıklama:**  
**Completing the Network Printer Installation Wizard** ekranında, kurulum sonucu görüntülenir ve test sayfası seçenekleri sunulur.

**Ekran Görüntüsü Detayları:**
- **Completing the Network Printer Installation Wizard** başlıklı ekran
- **Status** bölümünde iki başarılı işlem:
  - [✓] **Driver installation succeeded.**
  - [✓] **Printer installation succeeded.**
- Onay mesajı: **"Your printer has been installed successfully."**
- Sonraki adımlar için iki seçenek:
  - [x] **Print test page** (seçili)
  - [ ] Add another printer
- **Finish** butonu etkin durumda

✅ Kurulumun başarıyla tamamlandığını doğrulayın ve **Finish** butonuna tıklayın.

---

### Adım 16: Print Management'te Yazıcının Görünümü

![Adım 16](Images/16.png)

**Açıklama:**  
Yeni eklenen yazıcının Print Management konsolunda nasıl görüntülendiği gösterilir. Yazıcının durumu, kuyruktaki işler ve diğer teknik bilgiler bu ekranda yer alır.

**Ekran Görüntüsü Detayları:**
- **Print Management** ekranı
- Sol panelde **Print Servers > Serifselen-WIN-SRV (local) > Printers**
- Sağ panelde eklenen yazıcı:
  - Printer Name: **Microsoft MS-XPS Class Driver 2**
  - Queue Status: **Ready**
  - Jobs In Queue: **0**
  - Server Name: **Serifselen-WIN-SRV (local)**
  - Driver Name: **Microsoft MS-XPS Class Driver 2**
  - Driver Version: **10.0.26100.4484**
  - Driver Type: **In-box (Type 4)**
- Yazıcıya ait durum göstergesi: **Ready** (yeşil ikon)

✅ Yazıcı başarıyla eklenmiş ve kullanıma hazırdır.

---

## 🔧 Teknik Konfigürasyon

### Güvenlik Duvarı Yapılandırması

Yazıcı servisleri için gerekli olan temel portlar:

| Hizmet | Port | Protokol |
|--------|------|----------|
| Print Spooler (RPC) | 135 | TCP |
| SMB/CIFS | 445 | TCP |
| RAW Printing | 9100 | TCP |
| Internet Printing | 80/443 | TCP |
| LPD Service | 515 | TCP |

### PowerShell ile Temel Yapılandırma

```powershell
# Print Management konsolunu açma
printmanagement.msc

# Tüm yazıcıları listeleme
Get-Printer | Format-Table Name, DriverName, PortName, Shared

# Test sayfası yazdırma
$printer = Get-CimInstance -ClassName Win32_Printer -Filter "Name='Microsoft MS-XPS Class Driver 2'"
$printer.PrintTestPage()
```

### Group Policy Entegrasyonu

Yazıcıları Grup İlkesi ile dağıtma:
1. Active Directory Users and Computers
2. İlgili OU'ya sağ tıklayıp Group Policy Management
3. Yeni GPO oluşturun veya mevcut birini düzenleyin
4. User Configuration → Preferences → Control Panel Settings → Printers
5. New → Shared Printer ekleyin
6. UNC path belirtin: `\\Serifselen-WIN-SRV\Microsoft MS-XPS Class Driver 2`

---

## ✅ Doğrulama ve Test

### Temel Kontroller
1. **Yazıcı Durumu:** Print Management ekranında "Ready" durumunda olmalı
2. **Test Sayfası:** Yazıcıya sağ tıklayıp "Print Test Page" seçeneği ile test edilmeli
3. **Ağ Erişimi:** İstemci makineden `\\Serifselen-WIN-SRV\Microsoft MS-XPS Class Driver 2` adresine erişilebilmeli
4. **Yazdırma İşlemi:** Test belgesi yazdırılarak işlevsellik doğrulanmalı

### Sorun Giderme Adımları
- Yazıcı offline durumdaysa:
  - Print Spooler servisini yeniden başlatın
  - Yazıcı bağlantısını kontrol edin
- Sürücü sorunları için:
  - Güncelleştirilmiş sürücüleri yükleyin
  - Type 4 sürücüler tercih edin
- Paylaşım sorunları için:
  - SMB protokolünün etkin olduğunu kontrol edin
  - Güvenlik duvarı kurallarını gözden geçirin

---

## 📜 Doküman Bilgileri

| Özellik | Değer |
|---------|-------|
| **Yazar** | Serif SELEN |
| **Tarih** | 15 Kasım 2025 |
| **Versiyon** | 2.0 |
| **Platform** | VMware Workstation Pro 17 |
| **İşletim Sistemi** | Windows Server 2025 Standard Evaluation |
| **Etki Alanı Adı** | `Serifselen.local` |
| **Sunucu Adı** | `Serifselen-WIN-SRV` |
| **Yazıcı IP** | `192.168.31.201` |
| **Test Yazıcı** | Microsoft MS-XPS Class Driver 2 |
| **Lisans** | Evaluation (180 gün) |

**Kurulan Bileşenler:**
- ✅ Print and Document Services
- ✅ Print Server
- ✅ Internet Printing
- ✅ LPD Service
- ✅ Print Management Tools
- ✅ Web Server (IIS)
- ✅ .NET Framework 4.8

> ⚠️ **Önemli Not:** Bu doküman eğitim ve test ortamları için hazırlanmıştır. Üretim ortamlarında lisanslı yazılım ve güvenlik önlemleri kullanılmalıdır.

> 📧 **Destek İçin**: [mserifselen@gmail.com](mailto:mserifselen@gmail.com)  
> 🔗 **GitHub Repository**: [https://github.com/serifselen/Print-and-Document-Services-Kurulumu](https://github.com/serifselen/Print-and-Document-Services-Kurulumu)