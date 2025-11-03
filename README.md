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
- Etki alanına katılım (DOMAIN.serifselen.local)
- Ağ yazıcısı erişimi (192.168.31.201)

---

## 🖥️ Print and Document Services Kurulum Adımları

### Adım 1: Server Manager Ana Ekranı

![Adım 1](Images/1.png)

**Açıklama:**  
Server Manager açıldığında ana ekranda **"QUICK START"** bölümü görünür. Burada:
- **Configure this local server**
- **Add roles and features**
- **Add other servers to manage**

seçenekleri yer alır.

✅ Print and Document Services kurulumuna başlamak için  
**"Add roles and features"** bağlantısına tıklayın.

> 💡 **Pro Tip:** Server Manager, tüm Windows Server rollerinin ve özelliklerinin yönetildiği merkezi araçtır.

---

### Adım 2: "Add Roles and Features Wizard" Başlatma

![Adım 2](Images/2.png)

**Açıklama:**  
**Before You Begin** ekranında, kurulum öncesi ön koşullar özetlenir:
- Güçlü bir yönetici şifresi
- Statik IP yapılandırması
- Güncel sistem yamaları

Bu sayfa yalnızca bilgilendiricidir.  
➡️ **Next** butonuna tıklayarak devam edin.

---

### Adım 3: Kurulum Türü Seçimi

![Adım 3](Images/3.png)

**Açıklama:**  
**Installation Type** ekranında iki seçenek sunulur:
- ✅ **Role-based or feature-based installation** → Roller veya özellikler eklemek için
- ❌ Remote Desktop Services installation → Uzak masaüstü hizmetleri için

✅ **"Role-based or feature-based installation"** seçeneğini işaretleyin.  
➡️ **Next** butonuna tıklayın.

---

### Adım 4: Hedef Sunucu Seçimi

![Adım 4](Images/4.png)

**Açıklama:**  
**Server Selection** ekranında:
- **Name**: `DOMAIN`
- **IP Address**: `192.168.31.100`
- **Operating System**: `Windows Server 2025 Standard Evaluation`

gibi bilgiler görüntülenir.

✅ Kurulum yapılacak sunucu zaten seçili gelir. Doğru sunucuyu seçtiğinizden emin olduktan sonra  
➡️ **Next** butonuna tıklayın.

---

### Adım 5: Print and Document Services Rol Seçimi

![Adım 5](Images/5.png)

**Açıklama:**  
**Server Roles** listesinden **"Print and Document Services"** kutusunu işaretleyin.

Sistem, bu rol için gerekli yönetim araçlarını önerir:
- Group Policy Management
- Print and Document Services Tools
- Print Server Tools
- Internet Printing Client

✅ **"Include management tools (if applicable)"** seçeneği otomatik işaretlenir.  
➡️ **Add Features** butonuna tıklayıp **Next** butonuna geçin.

---

### Adım 6: Rol Hizmetlerinin Seçimi

![Adım 6](Images/6.png)

**Açıklama:**  
**Role Services** ekranında aşağıdaki hizmetler seçilir:
- ✅ **Print Server** → Temel yazıcı servisi
- ✅ **Internet Printing** → Web üzerinden yazdırma desteği
- ✅ **LPD Service** → UNIX/Linux sistemlerden yazdırma desteği

**Not:**  
Internet Printing hizmeti otomatik olarak Web Server (IIS) rolünü de yükler.

✅ Gerekli tüm hizmetleri seçtikten sonra **Next** butonuna tıklayın.

---

### Adım 7: Kurulum Öncesi Bilgilendirme Ekranı

![Adım 7](Images/7.png)

**Açıklama:**  
**Things to Note** ekranında:
- Type 3 ve Type 4 sürücü farkları
- 32-bit istemci desteği
- Güvenlik ve performans önerileri

> ⚠️ **Önemli Uyarı:**  
> Type 3 sürücüler (kernel-mode) güvenlik açığı oluşturabilir. Microsoft, Type 4 sürücülerin (user-mode) kullanılmasını önerir.

✅ Bu ekran sadece bilgilendirme amaçlıdır. **Next** butonuna tıklayarak devam edin.

---

### Adım 8: Kurulum Onayı ve Başlatma

![Adım 8](Images/8.png)

**Açıklama:**  
**Confirm installation selections** ekranında:
- **"Include management tools"** seçeneği işaretli olmalıdır
- Yüklenecek bileşenler listelenir:
  - Print and Document Services
  - .NET Framework 4.8
  - Web Server (IIS)
  - Yönetim araçları

✅ Kurulum özetini kontrol edin ve **Install** butonuna tıklayarak kurulumu başlatın.

> ⚠️ **Uyarı:** Kurulum sırasında sunucunun yeniden başlatılması gerekebilir. "Restart if required" seçeneğini işaretleyin.

---

## ⚙️ Print Management Konsolu

### Adım 9: Print Management Konsoluna Erişim

![Adım 9](Images/9.png)

**Açıklama:**  
Kurulum tamamlandıktan sonra:
- **Start Menu** üzerinden **Print Management** aranır
- Alternatif: `Win + R` > `printmanagement.msc`

✅ Araç başarıyla açıldığında sol panelde:
- Print Servers
- All Drivers
- Forms
- Ports
- Printers

bölümleri görüntülenir.

---

### Adım 10: Yazıcı Ekleme Menüsü

![Adım 10](Images/10.png)

**Açıklama:**  
Print Management ekranında:
- Sol panelde **Printers** bölümüne sağ tıklayın
- Açılan menüde **Add Printer...** seçeneği seçilir

✅ Bu işlem, yeni yazıcı ekleme sihirbazını başlatır.

---

## 🌐 Ağ Yazıcısı Yapılandırması

### Adım 11: Kurulum Yöntemi Seçimi

![Adım 11](Images/11.png)

**Açıklama:**  
**Network Printer Installation Wizard** ekranında:
- **Add a printer using a TCP/IP address or hostname** seçeneği seçilir
- Diğer seçenekler:
  - Search the network for printers
  - Add a local printer

✅ **Next** butonuna tıklayarak devam edin.

---

### Adım 12: Yazıcı Ağ Ayarları

![Adım 12](Images/12.png)

**Açıklama:**  
**Printer Address** ekranında:
- **Hostname or IP address**: `192.168.31.201` (yazıcının IP'si)
- **Port Name**: `192.168.31.201` (otomatik oluşturulur)
- **Auto detect the printer driver to use** seçeneği işaretli

✅ Yazıcı IP'nizi doğru girdiğinizden emin olun. **Next** butonuna tıklayın.

---

### Adım 13: Yazıcı Sürücüyü Seçimi

![Adım 13](Images/13.png)

**Açıklama:**  
**Printer Driver** ekranında üç seçenek sunulur:
- **Use the printer driver that the wizard selected** → Otomatik tespit
- **Use an existing printer driver on the computer** → Sistemde mevcut sürücü
- **Install a new driver** → Manuel sürücü yükleme

✅ **Microsoft MS-XPS Class Driver 2** sürücüsünü seçin.  
➡️ **Next** butonuna tıklayarak devam edin.

> 💡 **Not:** Gerçek yazıcılar için üreticinin resmi sürücüsünü yüklemeniz önerilir.

---

### Adım 14: Yazıcı Adı ve Paylaşım Ayarları

![Adım 14](Images/14.png)

**Açıklama:**  
**Printer Name and Sharing Settings** ekranında:
- **Printer name**: `Microsoft MS-XPS Class Driver 2`
- **Share this printer**: ✅ İşaretli (ağda paylaşılacaksa)
- **Share name**: `XPS_PRINTER`
- **Location**: `Server Room`
- **Comment**: `Test yazıcı - sanal`

✅ Paylaşım ayarlarını doğru yapılandırdıktan sonra **Next** butonuna tıklayın.

---

### Adım 15: Kurulum Tamamlanması

![Adım 15](Images/1.png)

**Açıklama:**  
**Completing the Network Printer Installation Wizard** ekranında:
- **Print test page** seçeneği işaretlenebilir
- Kurulum tamamlandıktan sonra **Finish** butonuna tıklanır

✅ Test sayfası basarak yazıcının çalıştığını doğrulayın.

---

### Adım 16: Print Management'te Yazıcının Görünümü

![Adım 16](Images/2.png)

**Açıklama:**  
Print Management ekranında:
- Yeni eklenen yazıcı **Printers** bölümünde listelenir
- **Status**: `Ready`
- **Jobs in Queue**: `0`
- **Driver**: `Microsoft MS-XPS Class Driver 2`

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
6. UNC path belirtin: `\\SERVERNAME\XPS_PRINTER`

---

## ✅ Doğrulama ve Test

### Temel Kontroller
1. **Yazıcı Durumu:** Print Management ekranında "Ready" durumunda olmalı
2. **Test Sayfası:** Yazıcıya sağ tıklayıp "Print Test Page" seçeneği ile test edilmeli
3. **Ağ Erişimi:** İstemci makineden `\\SERVERNAME\XPS_PRINTER` adresine erişilebilmeli
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
| **Tarih** | Aralık 2025 |
| **Versiyon** | 1.0 |
| **Platform** | VMware Workstation Pro 17 |
| **İşletim Sistemi** | Windows Server 2025 Standard Evaluation |
| **Etki Alanı Adı** | `DOMAIN.serifselen.local` |
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