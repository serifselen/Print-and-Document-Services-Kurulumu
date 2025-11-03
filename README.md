# Windows Server 2025 - Yazıcı ve Belge Hizmetleri Kurulum Rehberi

## 📋 İçindekiler
- [Genel Bakış](#genel-bakış)
- [Sistem Gereksinimleri](#sistem-gereksinimleri)
- [Kurulum Adımları](#kurulum-adımları)
- [Ağ Yazıcısı Yapılandırması](#ağ-yazıcısı-yapılandırması)
- [Teknik Konfigürasyon](#teknik-konfigürasyon)
- [Sorun Giderme](#sorun-giderme)

---

## 🎯 Genel Bakış

Bu rehber, Windows Server 2025 işletim sistemi üzerinde **Print and Document Services** rolünün kurulumunu ve ağ yazıcısı ekleme işlemlerini adım adım açıklamaktadır. Bu kurulum ile merkezi yazıcı yönetimi sağlayabilir, ağ yazıcılarını yönetebilir ve çoklu platform yazdırma desteği sunabilirsiniz.

**Önemli Not:** Bu kurulumdan önce Active Directory ve DNS yapılandırmasının tamamlanmış olması gerekmektedir.

---

## 🖥️ Sistem Gereksinimleri

### Donanım Gereksinimleri
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
- Etki alanına katılım (DOMAIN.serifesien.local)
- Ağ yazıcısı erişimi (192.168.31.201)

---

## 🚀 Kurulum Adımları

### 1. Adım: Server Manager'ı Başlatma

Sunucu Yöneticisi'ni açarak "Rol ve Özellik Ekle" sihirbazını başlatın.

![Server Manager Dashboard](Images/1.png)
*Sunucu Yöneticisi Dashboard - Rol ve özellik ekleme sihirbazının başlatılacağı ana yönetim konsolu*

### 2. Adım: Print and Document Services Rolünü Seçme

Rol seçim ekranında **Print and Document Services** rolünü seçin. Bu rol, yazıcı ve belge hizmetlerinin merkezi yönetimini sağlar.

![Print and Document Services Seçimi](Images/3.png)
*Rol seçim ekranı - Print and Document Services rolünün seçildiği ve Type 3/Type 4 sürücü destek bilgilerinin görüntülendiği ekran*

### 3. Adım: Yönetim Araçlarının Eklenmesi

Print and Document Services rolü seçildiğinde, gerekli yönetim araçlarının eklenmesi için aşağıdaki adımları izleyin:

- **Print and Document Services Tools** seçeneğini işaretleyin
- **Include management tools** seçeneğini aktif edin
- **Add Features** butonuna tıklayın

![Yönetim Araçları Ekleme](Images/2.png)
*Gerekli yönetim araçlarının eklenmesi - Print and Document Services Tools bileşeninin seçimi*

### 4. Adım: Rol Servislerinin Seçimi

Aşağıdaki rol servislerini seçerek kurulumu tamamlayın:

| Rol Servisi | Açıklama | Gereksinimler |
|-------------|----------|---------------|
| **Print Server** | Temel yazıcı sunucusu işlevleri | Zorunlu |
| **Internet Printing** | Web arayüzü üzerinden yönetim | IIS gerektirir |
| **LPD Service** | UNIX/Linux istemci desteği | İsteğe bağlı |

![Rol Servisleri Seçimi](Images/4.png)
*Rol servisleri seçim ekranı - Print Server, Internet Printing ve LPD Service bileşenlerinin seçimi*

### 5. Adım: Kurulum Onayı

Kurulum özetini kontrol edin ve **Install** butonuna tıklayarak kurulumu başlatın.

![Kurulum Onayı](Images/5.png)
*Kurulum onay ekranı - Seçilen bileşenlerin özet görünümü ve kurulum başlatma*

---

## ⚙️ Ağ Yazıcısı Yapılandırması

### 6. Adım: Print Management Konsolunu Açma

Kurulum tamamlandıktan sonra Print Management konsolunu açın:

```powershell
# Yol: Server Manager -> Tools -> Print Management
```

![Print Management Konsolu](Images/7.png)
*Print Management konsolu - Yazıcı yönetimi ve sürücü yönetimi merkezi arayüzü*

### 7. Adım: Yazıcı Ekleme Sihirbazını Başlatma

Print Management konsolundan **Add Printer** seçeneğini seçin.

![Yazıcı Ekleme Menüsü](Images/8.png)
*Yazıcı ekleme menüsü - Add Printer seçeneğinin bulunduğu arayüz*

### 8. Adım: Kurulum Yöntemi Seçimi

Ağ yazıcısı eklemek için aşağıdaki seçeneği işaretleyin:

**"Add an IPP, TCP/IP, or Web Services Printer by IP address or hostname"**

![Kurulum Yöntemi Seçimi](Images/9.png)
*Kurulum yöntemi seçimi - TCP/IP, IPP veya Web Services protokolleri ile ağ yazıcısı ekleme*

### 9. Adım: Yazıcı Ağ Ayarları

Aşağıdaki ağ ayarlarını girerek devam edin:

| Ayar | Değer | Açıklama |
|------|-------|----------|
| **Type of Device** | TCP/IP Device | Ağ yazıcısı türü |
| **Host name or IP address** | 192.168.31.201 | Yazıcının ağ adresi |
| **Port name** | 192.168.31.201 | Otomatik oluşturulan port adı |

![Yazıcı Ağ Ayarları](Images/10.png)
*Yazıcı ağ ayarları - TCP/IP cihaz türü ve IP adresi yapılandırması*

### 10. Adım: Yazıcı Sürücüsünü Yükleme

Sürücü yükleme işlemi için aşağıdaki adımları izleyin:

- **Install a new driver** seçeneğini seçin
- **Manufacturer** bölümünden **Microsoft**'u seçin
- **Printers** listesinden **Microsoft MS-XPS Class Driver 2**'yi seçin

![Sürücü Seçim Ekranı](Images/11.png)
*Sürücü seçim ekranı - Yeni sürücü yükleme seçeneğinin seçimi*

![Sürücü Model Seçimi](Images/12.png)
*Sürücü model seçimi - Microsoft MS-XPS Class Driver 2'nin seçimi ve dijital imza bilgisi*

### 11. Adım: Yazıcı Paylaşım Ayarları

Aşağıdaki paylaşım ayarlarını girerek yazıcıyı ağ üzerinden paylaşın:

| Ayar | Değer | Açıklama |
|------|-------|----------|
| **Printer Name** | Microsoft MS-XPS Class Driver 2 | Sistemde görünecek yazıcı adı |
| **Share this printer** | Evet | Ağ paylaşımını aktif et |
| **Share Name** | Microsoft MS-XPS Class Driver 2 | Ağ üzerinden görünecek ad |

![Paylaşım Ayarları](Images/13.png)
*Yazıcı paylaşım ayarları - Yazıcı adı ve paylaşım ayarlarının yapılandırılması*

### 12. Adım: Kurulumun Tamamlanması

Kurulumun başarıyla tamamlandığını aşağıdaki mesajlarla doğrulayın:

- ✅ **Driver installation succeeded**
- ✅ **Printer installation succeeded**

![Kurulum Tamamlandı](Images/14.png)
*Kurulum tamamlama ekranı - Başarılı kurulum mesajları ve test sayfası yazdırma seçeneği*

---

## 🔧 Teknik Konfigürasyon

### Yazıcı Sürücü Türleri ve Özellikleri

| Özellik | Type 3 (v3) Sürücü | Type 4 (v4) Sürücü |
|---------|-------------------|-------------------|
| **Güvenlik Modeli** | Kernel Mode | User Mode |
| **Kullanıcı İzinleri** | Yönetici hakları gerekli | Yönetici hakları gerekmez |
| **32/64-bit Desteği** | Ayrı sürücüler gerekli | Tek sürücü yeterli |
| **Dijital İmza** | Zorunlu değil | Zorunlu |
| **Microsoft Önerisi** | ❌ | ✅ |

### Güvenlik Yapılandırması

```powershell
# Point and Print Restrictions politikası
Computer Configuration -> Administrative Templates -> Printers
- Point and Print Restrictions: Enabled
- Users can only point and print to these servers: 192.168.31.201
```

### Ağ Güvenlik Ayarları

```powershell
# Gerekli portların açılması
New-NetFirewallRule -DisplayName "Print Spooler" -Direction Inbound -Protocol TCP -LocalPort 135,445 -Action Allow
New-NetFirewallRule -DisplayName "Internet Printing" -Direction Inbound -Protocol TCP -LocalPort 80,443 -Action Allow
```

---

## 🛠️ Sorun Giderme

### Sık Karşılaşılan Sorunlar ve Çözümleri

#### Yazıcı Bağlantı Sorunları
```powershell
# Yazıcı durumunu kontrol etme
Get-Printer -ComputerName localhost | Format-Table Name, PrinterStatus, Shared

# Ağ bağlantısını test etme
Test-NetConnection -ComputerName 192.168.31.201 -Port 9100

# Spooler servisini yeniden başlatma
Restart-Service -Name Spooler -Force
```

#### Sürücü Sorunları
```powershell
# Yüklü sürücüleri listeleme
Get-PrinterDriver -ComputerName localhost | Format-Table Name, Manufacturer, DriverVersion

# Sorunlu sürücüyü kaldırma ve yeniden yükleme
Remove-PrinterDriver -Name "Microsoft MS-XPS Class Driver 2"
Add-PrinterDriver -Name "Microsoft MS-XPS Class Driver 2"
```

#### Performans İzleme
```powershell
# Yazıcı kuyruğunu izleme
Get-PrintJob -PrinterName "Microsoft MS-XPS Class Driver 2"

# Performans sayaçlarını kontrol etme
Get-Counter "\Print Queue(*)\Jobs" -SampleInterval 5 -MaxSamples 10
```

### Kurulum Sonrası Kontrol Listesi

- [ ] Yazıcı "Ready" durumunda görünüyor
- [ ] Test sayfası başarıyla yazdırılıyor
- [ ] Ağ üzerinden erişim sağlanabiliyor
- [ ] Kullanıcı izinleri doğru çalışıyor
- [ ] Grup politikası uygulanıyor

---

## ✅ Sonuç

Bu rehber, Windows Server 2025 üzerinde **Print and Document Services** rolünün başarılı bir şekilde kurulumunu ve ağ yazıcısı yapılandırmasını tamamlamanızı sağlamıştır.

### 🎯 Başarı Metrikleri
- ✅ Yazıcı sunucusu rolü başarıyla yüklendi
- ✅ Ağ yazıcısı başarıyla eklendi ve paylaşıma açıldı
- ✅ Type 4 sürücülerle güvenlik en iyi uygulamaları uygulandı
- ✅ Çoklu platform desteği sağlandı

### 🔄 Bakım Önerileri
- Düzenli yazıcı sürücü güncellemeleri
- Performans izleme ve optimizasyon
- Güvenlik güncellemelerinin takibi
- Yedekleme ve felaket kurtarma planı

> **Önemli:** Üretim ortamlarında bu kurulumu gerçekleştirmeden önce test ortamında doğrulama yapmanız önerilir.

---

## 📞 Destek

Sorunlarla karşılaşırsanız aşağıdaki adımları izleyin:

1. Windows Event Logları kontrol edin: `Event Viewer -> Applications and Services Logs -> Microsoft -> Windows -> PrintService`
2. Print Spooler servis durumunu doğrulayın: `services.msc`
3. Ağ bağlantısını test edin: `ping 192.168.31.201`
4. Güvenlik duvarı ayarlarını kontrol edin

---

**Not:** Bu rehber, Windows Server 2025 için güncel olarak hazırlanmıştır. Önceki Windows Server sürümlerinde bazı adımlar farklılık gösterebilir.
