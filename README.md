# 🖥️ Windows Server 2025 Üzerinde AD DS ve DNS Sunucu Kurulum Kılavuzu

![Active Directory ve DNS Kurulum](https://i.imgur.com/placeholder.png)

> **EĞİTİM AMAÇLI NOT**  
> Bu doküman eğitim ve test ortamları için hazırlanmıştır. Üretim ortamlarında lisanslı yazılımlar ve kapsamlı güvenlik önlemleri kullanılmalıdır.

---

## 📋 **Giriş ve Hedefler**

Bu kapsamlı rehber, **Windows Server 2025 Standard Evaluation** sürümüne **Active Directory Domain Services (AD DS)** ve **DNS Server** rollerinin nasıl kurulacağını adım adım açıklar. Kurulum tamamlandığında, sunucunuz bir **Domain Controller** olarak görev yapacak ve kurumsal kimlik yönetimi için temel altyapıyı oluşturacaktır.

### 🎯 **Bu Kurulum İle Gerçekleştirilecekler:**
- Yeni bir etki alanı ormanı (forest) oluşturulması
- Temel DNS yapılandırmasının yapılması
- Domain Controller yetkilerinin atanması
- Kullanıcı ve grup yönetim altyapısının kurulması

---

## ⚙️ **Ön Koşullar**

Kuruluma başlamadan önce aşağıdaki hazırlıkların yapılması **kritik öneme** sahiptir:

| Özellik | Gereksinim | Kontrol |
|---------|------------|---------|
| Sunucu Donanımı | En az 4 GB RAM, 32 GB disk alanı | ✅ |
| İşletim Sistemi | Windows Server 2025 Standard Evaluation | ✅ |
| Ağ Yapılandırması | **Statik IP adresi** ayarlanmış olmalı | ✅ |
| Yönetici Hesabı | Yerel yönetici haklarına sahip hesap | ✅ |
| Güvenlik | Güçlü yönetici şifresi tanımlanmış olmalı | ✅ |
| Sistem Güncellemeleri | Tüm Windows Update'ler yapılmış olmalı | ✅ |

> **DİKKAT:** Dinamik IP adresi kullanıyorsanız, mutlaka sunucuya statik IP tanımlayın. Aksi takdirde Active Directory hizmetleri çalışmaz.

---

## 🚀 **Kurulum Adımları**

### **1. Server Manager Ana Ekranı**
![Server Manager Başlangıç Ekranı](https://i.imgur.com/placeholder1.png)

Server Manager açıldığında sol üst köşede bulunan **"QUICK START"** panelinden:
- **Configure this local server**
- **Add roles and features** 
- **Add other servers to manage**

seçenekleri görülecektir. AD DS kurulumuna başlamak için **"Add roles and features"** bağlantısına tıklayın.

---

### **2. "Add Roles and Features Wizard" Başlatma**
![Before You Begin Ekranı](https://i.imgur.com/placeholder2.png)

**Before You Begin** ekranında kurulum öncesi kontrol edilmesi gereken ön koşullar listelenir:
- Güçlü bir yönetici şifresi
- Statik IP yapılandırması
- Güncel sistem yamaları

Bu bilgilendirme ekranından sonra **Next** butonuna tıklayarak devam edin.

---

### **3. Kurulum Türü Seçimi**
![Installation Type Seçimi](https://i.imgur.com/placeholder3.png)

**Installation Type** ekranında iki seçenek sunulur:
- **Role-based or feature-based installation** ✅ *(SEÇİN)*
- Remote Desktop Services installation

Active Directory kurulumu için **"Role-based or feature-based installation"** seçeneğini işaretleyin ve **Next** butonuna tıklayın.

---

### **4. Hedef Sunucu Seçimi**
![Server Selection Ekranı](https://i.imgur.com/placeholder4.png)

**Server Selection** ekranında hedef sunucu bilgileri görüntülenir:
- **Name**: `DOMAIN`
- **IP Address**: `192.168.31.100`
- **Operating System**: `Windows Server 2025 Standard Evaluation`

Doğru sunucunun seçili olduğundan emin olduktan sonra **Next** butonuna tıklayın.

---

### **5. Active Directory Domain Services Rolü Seçimi**
![Server Roles Seçimi](https://i.imgur.com/placeholder5.png)

**Server Roles** listesinden **"Active Directory Domain Services"** kutusunu işaretleyin.

Sistem, bu rol için gerekli yönetim araçlarını önerecektir:
- Group Policy Management
- AD DS and AD LDS Tools
- Active Directory Administrative Center
- AD DS Snap-Ins and Command-Line Tools

> **ÖNEMLİ:** Açılır pencerede **"Add Features"** butonuna tıklayarak bu araçların da kurulmasını sağlayın. **"Include management tools (if applicable)"** seçeneğinin işaretli olduğundan emin olun ve **Next** butonuna tıklayın.

---

### **6. Deployment Configuration – Yeni Orman Oluşturma**
![Deployment Configuration](https://i.imgur.com/placeholder6.png)

AD DS kurulumu tamamlandıktan sonra **"Promote this server to a domain controller"** sihirbazı otomatik olarak açılacaktır.

Bu ekranda:
- ☑ **Add a new forest** seçeneğini işaretleyin
- **Root domain name** alanına: `serifselen.local` yazın

> **DİKKAT:** Eğer **"Verification of forest name failed"** uyarısı alırsanız:
> - Etki alanı adını basitleştirin (`ad.local` gibi)
> - DNS sunucusu ayarlarını kontrol edin
> - İnternet bağlantınız yoksa geçici olarak devre dışı bırakın

**Next** butonuna tıklayarak devam edin.

---

### **7. Domain Controller Seçenekleri**
![Domain Controller Options](https://i.imgur.com/placeholder7.png)

**Domain Controller Options** ekranında aşağıdaki ayarları yapın:
- **Forest functional level**: `Windows Server 2025`
- **Domain functional level**: `Windows Server 2025`
- ☑ **DNS server** *(Otomatik işaretlenecektir)*
- ☑ **Global Catalog (GC)**
- **DSRM password**: Güçlü bir şifre girin

> **BİLGİ:** DSRM (Directory Services Restore Mode) şifresi, acil durum kurtarma modu için gereklidir. Bu şifreyi kaybetmemeye özen gösterin.

---

### **8. Ön Koşul Denetimi**
![Prerequisites Check](https://i.imgur.com/placeholder8.png)

**Prerequisites Check** ekranında tüm ön koşul kontrolleri yapılır:
- ✅ **All prerequisite checks passed successfully** mesajı görüntülenmelidir
- ⚠️ **"A delegation for this DNS server cannot be created..."** uyarısı, mevcut bir DNS altyapısı yoksa ihmal edilebilir

Tüm kontroller başarılı olduğunda **Install** butonuna tıklayarak kurulumu başlatın.

---

### **9. Kurulum İlerleme Durumu**
![Installation Progress](https://i.imgur.com/placeholder9.png)

Kurulum sırasında aşağıdaki bileşenler yüklenir:
- Active Directory Domain Services
- Group Policy Management
- Remote Server Administration Tools
- AD DS Tools
- Active Directory PowerShell modülleri

**Kurulum tamamlandığında sunucu otomatik olarak yeniden başlatılır.** Bu süreç 5-10 dakika sürebilir.

---

### **10. Post-deployment Yapılandırma Uyarısı**
![Configuration Required Warning](https://i.imgur.com/placeholder10.png)

Sunucu yeniden başladığında Server Manager dashboard'unda sağ üst köşede bir uyarı simgesi belirecektir:

> **"Post-deployment Configuration**  
> **Configuration required for Active Directory Domain Services at DOMAIN**  
> **Promote this server to a domain controller"**

Bu uyarı, AD DS yapılandırmasının tamamlanmadığını gösterir. Uyarıya tıklayarak yapılandırmayı tamamlayabilir veya komut satırından `dcpromo` komutuyla devam edebilirsiniz.

---

## ✅ **Kurulum Sonrası Doğrulama**

Kurulum tamamlandığında sunucunuz:
- **serifselen.local** etki alanında bir **Domain Controller** olarak çalışmaktadır
- **DNS Server** hizmeti otomatik olarak yapılandırılmıştır
- **Active Directory Yönetim Araçları** sunucuda mevcuttur

Doğrulama için:
1. `dsa.msc` komutu ile Active Directory Users and Computers konsolunu açın
2. `dnsmgmt.msc` ile DNS Yöneticisini kontrol edin
3. Komut isteminde `dcdiag /test:dns` komutuyla DNS testi yapın

---

## 🛠️ **Kurulum Sonrası Önerilen Yapılandırmalar**

### **1. Kullanıcı ve Grup Yönetimi**
- Active Directory Users and Computers (ADUC) üzerinden ilk yönetici kullanıcılarını oluşturun
- Organizational Unit (OU) yapısını kurum hiyerarşinize göre oluşturun

### **2. Grup İlkesi (GPO) Yapılandırması**
- Varsayılan Domain Policy ve Default Domain Controllers Policy'leri düzenleyin
- Güvenlik politikaları, şifre karmaşıklığı kuralları tanımlayın
- Oturum kilitlenme sürelerini belirleyin

### **3. Diğer Sunucuları Etki Alanına Katma**
- Üye sunucuların `serifselen.local` etki alanına katılmasını sağlayın
- Domain membership için sunucularda statik DNS adresi olarak DC'nin IP'sini (`192.168.31.100`) tanımlayın

### **4. Yedekleme ve Kurtarma Planı**
- System State yedeklemesi alın (wbadmin veya VSS üzerinden)
- DSRM şifresini güvenli bir yerde saklayın
- AD veritabanı (ntds.dit) ve SYSVOL klasörlerinin durumunu düzenli kontrol edin

### **5. Güvenlik Duvarı ve Ağ İzolasyonu**
Aşağıdaki portların açık olduğundan emin olun:

| Protokol | Port Numarası | Hizmet |
|----------|---------------|--------|
| TCP | 53 | DNS |
| TCP/UDP | 88 | Kerberos |
| TCP/UDP | 135 | RPC Endpoint Mapper |
| TCP/UDP | 389 | LDAP |
| TCP | 445 | SMB (SYSVOL paylaşımı için) |
| TCP | 3268 | Global Catalog |
| TCP | 5722 | DFS Replication |

---

## ⚠️ **Sık Karşılaşılan Sorunlar ve Çözümleri**

| Sorun | Çözüm |
|-------|-------|
| **"DNS delegation failed"** | Mevcut bir DNS altyapısı yoksa bu uyarı dikkate alınmaz |
| **"Forest name verification failed"** | İnternete bağlı değilseniz, geçici olarak interneti kapatın veya daha basit bir domain adı kullanın |
| **Kurulum sonrası oturum açma sorunları** | Sunucu yeniden başlatıldıktan sonra, hesap adını `SERIFSLEN\administrator` formatında girin |
| **DNS kayıtları oluşturulamıyor** | DNS servisini yeniden başlatın: `Restart-Service DNS` |
| **Replication sorunları** | `repadmin /syncall` komutunu yönetici olarak çalıştırın |

---

## 📦 **Sistem ve Ortam Bilgileri**

| Özellik | Değer |
|---------|-------|
| **Yazar** | Serif SELEN |
| **Tarih** | 2 Kasım 2025 |
| **Platform** | VMware Workstation Pro 17 |
| **İşletim Sistemi** | Windows Server 2025 Standard Evaluation |
| **Etki Alanı Adı** | `serifselen.local` |
| **DNS Sunucusu** | 192.168.31.100 (yerel sunucu) |
| **IP Adresi** | 192.168.31.100/24 |
| **Gateway** | 192.168.31.2 |
| **DSRM Şifresi** | [Kayıtlı Güvenli Konumda] |
| **Lisans Tipi** | Evaluation (180 gün) |
| **GitHub Depo Adresi** | [https://github.com/serifselen/Active-Directory-ve-DNS-Kurulum](https://github.com/serifselen/Active-Directory-ve-DNS-Kurulum) |

---

## 🔗 **Faydalı Kaynaklar**

- [Microsoft Docs: AD DS Kurulumu](https://docs.microsoft.com/tr-tr/windows-server/identity/ad-ds/deploy/)
- [DNS ve Active Directory Tümleşimi](https://docs.microsoft.com/tr-tr/windows-server/networking/dns/dns-top)
- [Active Directory Sorun Giderme Rehberi](https://docs.microsoft.com/tr-tr/troubleshoot/windows-server/active-directory/welcome-active-directory)

---

> **EĞİTİM NOTU:** Bu doküman tamamen eğitim amaçlı hazırlanmıştır. Herhangi bir üretim ortamında kullanmadan önce gerekli testleri yapın ve Microsoft lisans gereksinimlerini karşılamanız gerektiğini unutmayın.

** hazırlanma tarihi: 2 Kasım 2025**  
**Doküman sürümü: 1.0**  
**Yazar: Serif SELEN** ✉️ serifselen@example.com