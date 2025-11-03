# Windows Server 2025 - Yazıcı ve Belge Hizmetleri Kurulum Rehberi

## 📋 İçindekiler
- [Genel Bakış](#-genel-bakış)
- [Önkoşullar](#-önkoşullar)
- [Kurulum Adımları](#-kurulum-adımları)
- [Yapılandırma](#-yapılandırma)
- [Sorun Giderme](#-sorun-giderme)

---

## 🎯 Genel Bakış

Bu rehber, Windows Server 2025 üzerinde **Print and Document Services** rolünün kurulumunu ve ağ yazıcısı yapılandırmasını adım adım açıklamaktadır.

> **Önemli Not:** Bu kurulum, Active Directory ve DNS yapılandırması tamamlanmış bir sunucu üzerinde gerçekleştirilmelidir.

---

## 🛠 Önkoşullar

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

---

## 🚀 Kurulum Adımları

### 1. Print and Document Services Rolünün Eklenmesi

#### 1.1. Server Manager'ı Açma
- Sunucu Yöneticisi'ni açın
- "Rol ve Özellik Ekle" seçeneğine tıklayın

![Server Manager Dashboard](Images/1.png)

#### 1.2. Yönetim Araçlarının Eklenmesi
- **Print and Document Services** rolünü seçin
- **Print and Document Services Tools** ekranında "Include management tools" seçeneğini işaretleyin
- **Add Features** butonuna tıklayın

![Yönetim Araçları Ekleme](Images/2.png)

#### 1.3. Rol Servislerinin Seçimi
Aşağıdaki rol servislerini seçin:

| Rol Servisi | Açıklama | Gereksinimler |
|-------------|----------|---------------|
| **Print Server** | Temel yazıcı sunucusu işlevleri | Zorunlu |
| **Internet Printing** | Web arayüzü üzerinden yönetim | IIS gerektirir |
| **LPD Service** | UNIX/Linux istemci desteği | İsteğe bağlı |

![Rol Servisleri Seçimi](Images/4.png)

#### 1.4. Kurulum Onayı
Kurulum özetini kontrol edin ve **Install** butonuna tıklayın.

![Kurulum Onayı](Images/5.png)

### 2. Print Management Konsolu

Kurulum tamamlandıktan sonra Print Management konsolunu açın:

```powershell
# Yol: Server Manager -> Tools -> Print Management
```

![Print Management Konsolu](Images/7.png)

---

## ⚙️ Yapılandırma

### 3. Ağ Yazıcısı Ekleme

#### 3.1. Yazıcı Kurulum Sihirbazı
- Print Management konsolundan **Add Printer** seçeneğini seçin
- **Add an IPP, TCP/IP, or Web Services Printer by IP address or hostname** seçeneğini işaretleyin

![Kurulum Yöntemi Seçimi](Images/9.png)

#### 3.2. Yazıcı Ağ Ayarları
| Ayar | Değer |
|------|-------|
| **Type of Device** | TCP/IP Device |
| **Host name or IP address** | 192.168.31.201 |
| **Port name** | 192.168.31.201 |

![Yazıcı Ağ Ayarları](Images/10.png)

#### 3.3. Yazıcı Sürücüsü Yükleme
- **Install a new driver** seçeneğini seçin
- **Manufacturer:** Microsoft
- **Printers:** Microsoft MS-XPS Class Driver 2

![Sürücü Seçimi](Images/11.png)
![Sürücü Model Seçimi](Images/12.png)

#### 3.4. Yazıcı Paylaşım Ayarları
| Ayar | Değer |
|------|-------|
| **Printer Name** | Microsoft MS-XPS Class Driver 2 |
| **Share this printer** | Evet |
| **Share Name** | Microsoft MS-XPS Class Driver 2 |

![Paylaşım Ayarları](Images/13.png)

#### 3.5. Kurulum Tamamlama
Kurulumun başarıyla tamamlandığını doğrulayın.

![Kurulum Tamamlandı](Images/14.png)

---

## 🔧 Sorun Giderme

### Sık Karşılaşılan Sorunlar ve Çözümleri

#### 1. Yazıcı Bağlantı Sorunları
```powershell
# Yazıcı durumunu kontrol et
Get-Printer -ComputerName localhost

# Ağ bağlantısını test et
Test-NetConnection -ComputerName 192.168.31.201 -Port 9100

# Spooler servisini yeniden başlat
Restart-Service -Name Spooler -Force
```

#### 2. Sürücü Sorunları
```powershell
# Yüklü sürücüleri listele
Get-PrinterDriver -ComputerName localhost

# Sürücüyü kaldır ve yeniden yükle
Remove-PrinterDriver -Name "Microsoft MS-XPS Class Driver 2"
```

#### 3. İzin Sorunları
- Yazıcı paylaşım izinlerini kontrol edin
- Güvenlik duvarı ayarlarını doğrulayın
- Grup politikası ayarlarını kontrol edin

### Performans İzleme
```powershell
# Yazıcı kuyruğunu izle
Get-PrintJob -PrinterName "Microsoft MS-XPS Class Driver 2"

# Performans sayaçlarını kontrol et
Get-Counter "\Print Queue(*)\Jobs"
```

---

## ✅ Doğrulama ve Test

### Kurulum Sonrası Kontroller
- [ ] Yazıcı "Ready" durumunda görünüyor
- [ ] Test sayfası başarıyla yazdırılıyor
- [ ] Ağ üzerinden erişim sağlanabiliyor
- [ ] Kullanıcı izinleri doğru çalışıyor

### Komut Satırı Doğrulama
```powershell
# Tüm yazıcıları listele
Get-Printer | Format-Table Name, PrinterStatus, Shared

# Yazıcı sürücülerini kontrol et
Get-PrinterDriver | Format-Table Name, DriverVersion
```

---

## 📞 Destek

Sorunlarla karşılaşırsanız aşağıdaki adımları izleyin:

1. Windows Event Logları kontrol edin
2. Print Spooler servis durumunu doğrulayın
3. Ağ bağlantısını test edin
4. Güvenlik duvarı ayarlarını kontrol edin

---

## 🔗 Yararlı Bağlantılar

- [Windows Server 2025 Kurulum Rehberi](https://github.com/serifselen/Windows-Server-2025-Kurulum)
- [Active Directory ve DNS Kurulum Rehberi](https://github.com/serifselen/Active-Directory-ve-DNS-Kurulum)
- [Microsoft Print Services Dokümantasyonu](https://docs.microsoft.com/tr-tr/windows-server/administration/print-services/print-services-overview)

---

**Not:** Bu rehber, Windows Server 2025 için güncel olarak hazırlanmıştır. Önceki sürümlerde bazı adımlar farklılık gösterebilir.

---
*Son güncelleme: Aralık 2024*