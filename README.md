# 🖥️ Windows Server 2025 Üzerinde AD DS ve DNS Kurulumu

> ⚠️ **Not:** Bu rehber, **Windows Server 2025 Standard Evaluation** sürümüne göre hazırlanmıştır. Üretim ortamlarında lisanslı bir sürüm kullanılmalıdır.

Bu rehber, Windows Server 2025 sistemine **Active Directory Domain Services (AD DS)** ve **DNS Server** rollerinin nasıl kurulacağını adım adım açıklar. Kurulum, `Server Manager` aracılığıyla gerçekleştirilir.

---

## 📑 İçindekiler

- [Gereksinimler](#-gereksinimler)
- [Adım 1: Server Manager Ana Ekranı](#-adım-1-server-manager-ana-ekranı)
- [Adım 2: “Add Roles and Features Wizard” Başlatma](#-adım-2-add-roles-and-features-wizard-başlatma)
- [Adım 3: Kurulum Türü Seçimi](#-adım-3-kurulum-türü-seçimi)
- [Adım 4: Hedef Sunucu Seçimi](#-adım-4-hedef-sunucu-seçimi)
- [Adım 5: Active Directory Domain Services Rolü Seçimi](#-adım-5-active-directory-domain-services-rolü-seçimi)
- [Adım 6: Deployment Configuration – Yeni Orman Oluşturma](#-adım-6-deployment-configuration--yeni-orman-oluşturma)
- [Adım 7: Domain Controller Seçenekleri](#-adım-7-domain-controller-seçenekleri)
- [Adım 8: Ön Koşul Denetimi](#-adım-8-ön-koşul-denetimi)
- [Adım 9: Kurulum İlerleme Durumu](#-adım-9-kurulum-ilerleme-durumu)
- [Adım 10: Post-deployment Yapılandırma Uyarısı](#-adım-10-post-deployment-yapılandırma-uyarısı)
- [Adım 11: AD DS Yapılandırması Tamamlandı](#-adım-11-ad-ds-yapılandırması-tamamlandı)
- [Adım 12: DNS Sunucusu Kontrolü](#-adım-12-dns-sunucusu-kontrolü)
- [Adım 13: Etki Alanı Kullanıcıları ve Grupları](#-adım-13-etki-alanı-kullanıcıları-ve-grupları)
- [Adım 14: Güvenlik ve En İyi Uygulamalar](#-adım-14-güvenlik-ve-en-iyi-uygulamalar)
- [✅ Kurulum Sonrası Öneriler](#-kurulum-sonrası-öneriler)
- [📚 Doküman Bilgileri](#-doküman-bilgileri)

---

## 🛠️ Gereksinimler

- Windows Server 2025 Standard Evaluation (veya lisanslı sürüm)
- Statik IP adresi yapılandırılmış sunucu (`192.168.31.100`)
- Güçlü bir yönetici şifresi
- Güncel sistem yamaları
- Internet bağlantısı (Windows Update için önerilir)

---

## 🚀 Adım 1: Server Manager Ana Ekranı

![1.png](Images/1.png)

**Açıklama:**  
Server Manager açıldığında sol üst köşede **“QUICK START”** bölümü görünür. Burada:
- **Configure this local server**
- **Add roles and features**
- **Add other servers to manage**

seçenekleri yer alır.

✅ AD DS kurulumuna başlamak için  
**“Add roles and features”** bağlantısına tıklayın.

> 💡 **Pro Tip:** Server Manager, tüm Windows Server rollerinin ve özelliklerinin yönetildiği merkezi araçtır. Başlangıçta her zaman bu pencereden başlayın.

---

## 🧩 Adım 2: “Add Roles and Features Wizard” Başlatma

![2.png](Images/2.png)

**Açıklama:**  
**Before You Begin** ekranında, kurulum öncesi ön koşullar özetlenir:
- Güçlü bir yönetici şifresi
- Statik IP yapılandırması
- Güncel sistem yamaları

Bu sayfa yalnızca bilgilendiricidir.  
➡️ **Next** butonuna tıklayarak devam edin.

---

## 📄 Adım 3: Kurulum Türü Seçimi

![3.png](Images/3.png)

**Açıklama:**  
**Installation Type** ekranında iki seçenek sunulur:
- ✅ **Role-based or feature-based installation** → Roller veya özellikler eklemek için
- ❌ Remote Desktop Services installation → Uzak masaüstü hizmetleri için

✅ **“Role-based or feature-based installation”** seçeneğini işaretleyin.  
➡️ **Next** butonuna tıklayın.

---

## 🔍 Adım 4: Hedef Sunucu Seçimi

![4.png](Images/4.png)

**Açıklama:**  
**Server Selection** ekranında:
- **Name**: `DOMAIN`
- **IP Address**: `192.168.31.100`
- **Operating System**: `Windows Server 2025 Standard Evaluation`

gibi bilgiler görüntülenir.

✅ Kurulum yapılacak sunucu zaten seçili gelir. Doğru sunucuyu seçtiğinizden emin olduktan sonra  
➡️ **Next** butonuna tıklayın.

---

## 📦 Adım 5: Active Directory Domain Services Rolü Seçimi

![5.png](Images/5.png)

**Açıklama:**  
**Server Roles** listesinden **“Active Directory Domain Services”** kutusunu işaretleyin.

Sistem, bu rol için gerekli yönetim araçlarını önerir:
- Group Policy Management
- AD DS and AD LDS Tools
- Active Directory Administrative Center
- AD DS Snap-Ins and Command-Line Tools

✅ **“Include management tools (if applicable)”** seçeneği otomatik işaretlenir.  
➡️ **Add Features** butonuna tıklayıp **Next** butonuna geçin.

---

## 🌲 Adım 6: Deployment Configuration – Yeni Orman Oluşturma

![6.png](Images/6.png)

**Açıklama:**  
AD DS kurulumu tamamlandıktan sonra **“Promote this server to a domain controller”** bağlantısıyla açılan sihirbazda:

- ☑ **Add a new forest** seçeneği işaretlenir
- **Root domain name**: `serifselen.local` girilir

⚠️ Eğer **“Verification of forest name failed”** uyarısı alırsanız:
- Etki alanı adını basitleştirin (`ad.local` gibi)
- DNS sunucusu ayarlarını kontrol edin

➡️ **Next** butonuna tıklayın.

> ⚠️ **Önemli Uyarı:** `.local` uzantılı domain adları yalnızca **test ortamları** için uygundur. Üretimde **kaydedilmiş bir domain** (örn: `corp.serifselen.com`) kullanılmalıdır.

---

## 🎯 Adım 7: Domain Controller Seçenekleri

![7.png](Images/7.png)

**Açıklama:**  
**Domain Controller Options** ekranında:

- **Forest functional level**: `Windows Server 2025`
- **Domain functional level**: `Windows Server 2025`
- ☑ **DNS server** → Otomatik olarak yüklenir
- ☑ **Global Catalog (GC)** → Varsayılan olarak seçilir
- **DSRM password**: Güçlü bir şifre girilir (Directory Services Restore Mode)

DSRM şifresi, acil durum kurtarma modu için gereklidir. Şifreyi güvenli bir yere kaydedin.

➡️ **Next** butonuna tıklayın.

---

## ✅ Adım 8: Ön Koşul Denetimi

![8.png](Images/8.png)

**Açıklama:**  
**Prerequisites Check** ekranında:

- ✅ **All prerequisite checks passed successfully** uyarıları görüntülenir.

⚠️ **“A delegation for this DNS server cannot be created…”** uyarısı, mevcut bir DNS altyapısı yoksa **ihmal edilebilir**.

➡️ **Install** butonuna tıklayarak kurulumu başlatın.

---

## 🔄 Adım 9: Kurulum İlerleme Durumu

![9.png](Images/9.png)

**Açıklama:**  
**Installation progress** ekranında yüklenen bileşenler listelenir:
- Active Directory Domain Services
- Group Policy Management
- Remote Server Administration Tools
- AD DS Tools
- Active Directory PowerShell modülleri

Kurulum tamamlandığında sunucu **otomatik olarak yeniden başlatılır**.

---

## ⚠️ Adım 10: Post-deployment Yapılandırma Uyarısı

![10.png](Images/10.png)

**Açıklama:**  
Sunucu yeniden başladığında `Server Manager` dashboard’unda sağ üst köşede bir uyarı simgesi belirir:

> **Post-deployment Configuration**  
> Configuration required for Active Directory Domain Services at DOMAIN  
> **Promote this server to a domain controller**

✅ Bu uyarı, AD DS yapılandırmasının tamamlanmadığını gösterir.

➡️ **Bağlantıya tıklayarak yapılandırmayı tamamlayabilirsiniz.**

> ❌ **Yanlış Bilgi Düzeltmesi:**  
> “komut satırından `dcpromo` ile devam edebilirsiniz” ifadesi **yanlıştır**.  
> `dcpromo` komutu **Windows Server 2012’den sonra kaldırılmıştır**.  
>  
> ✅ **Doğrusu:**  
> PowerShell ile `Install-ADDSDomainController` komutunu kullanın veya sihirbaz üzerinden devam edin.

---

## ✅ Adım 11: AD DS Yapılandırması Tamamlandı

![11.png](Images/11.png)

**Açıklama:**  
Yapılandırma tamamlandığında, aşağıdaki mesaj görüntülenir:

> **The configuration of Active Directory Domain Services completed successfully.**

Sunucu artık **serifselen.local** etki alanında bir **Domain Controller (Etki Alanı Denetleyicisi)** olarak çalışmaktadır.

➡️ **Close** butonuna tıklayarak sihirbazı kapatın.

> 💡 **Pro Tip:** Bu ekranda “Restart the destination server automatically if required” seçeneği işaretliyse, sunucu otomatik olarak yeniden başlar.

---

## 🌐 Adım 12: DNS Sunucusu Kontrolü

![12.png](Images/12.png)

**Açıklama:**  
DNS sunucusu, AD DS kurulumu sırasında otomatik olarak yüklenir. Kontrol etmek için:

1. `Server Manager` > `Tools` > `DNS`
2. Sol panelde `DOMAIN` > `Forward Lookup Zones` > `serifselen.local` açılır.
3. Burada `@` (root) record ve `_msdcs` alt alanı görülmelidir.

✅ DNS records otomatik oluşturulmuşsa, yapılandırma başarılı demektir.

> ⚠️ **Uyarı:** DNS record’ların eksik olması, etki alanına katılım sorunlarına neden olur.

---

## 👥 Adım 13: Etki Alanı Kullanıcıları ve Grupları

![13.png](Images/13.png)

**Açıklama:**  
AD DS kurulumu tamamlandıktan sonra ilk kullanıcıları oluşturmak gerekir.

1. `Server Manager` > `Tools` > `Active Directory Users and Computers`
2. `serifselen.local` altında:
   - `Users` klasörüne sağ tıkla > `New` > `User`
   - Örnek: `ITAdmin`, `HelpDesk`, `GuestUser`

✅ **Önerilen Gruplar:**
- `Domain Admins`: Sistem yönetimi
- `Enterprise Admins`: Çoklu etki alanı yönetimi
- `Schema Admins`: Şema değişiklikleri

> 💡 **En İyi Uygulama:** Her kullanıcıyı en az yetki seviyesindeki gruba ekleyin (Principle of Least Privilege).

---

## 🔒 Adım 14: Güvenlik ve En İyi Uygulamalar

![14.png](Images/14.png)

**Açıklama:**  
AD DS kurulumu tamamlandıktan sonra güvenlik önlemlerini uygulayın:

### ✅ 1. Güvenlik Duvarı Ayarları
- TCP 53 (DNS)
- TCP 88 (Kerberos)
- TCP 389 (LDAP)
- TCP 445 (SMB)
- TCP 3268 (Global Catalog)

### ✅ 2. Grup İlkesi (GPO) Yapılandırması
- `Default Domain Policy`’yi düzenleyin:
  - Şifre karmaşıklığı
  - Oturum açma deneme limiti
  - Güvenlik logları

### ✅ 3. Yedekleme Planı
- **System State** yedeklemesi alın.
- Windows Server Backup veya üçüncü parti araçlar (Veeam, Altaro) kullanın.

### ✅ 4. Güvenlik İzolasyonu
- DC’yi ayrı bir ağ segmentine yerleştirin.
- Güvenlik duvarı ile erişimi sınırlayın.

---

## ✅ Kurulum Sonrası Öneriler

- **Diğer Sunucuları Etki Alanına Katma:**  
  ```powershell
  Add-Computer -DomainName "serifselen.local" -Restart
  ```

- **İstemci Makineleri Etki Alanına Katma:**  
  - `Settings` > `Accounts` > `Access Work or School` > `Connect` > `Join this device to a local Active Directory domain`

- **Azure AD Connect Entegrasyonu:**  
  - Bulut ile şirket içi AD arasında senkronizasyon sağlar.

---

## 📚 Doküman Bilgileri

| Özellik | Değer |
|---|---|
| **Yazar** | Serif SELEN |
| **Tarih** | 2 Kasım 2025 |
| **Platform** | VMware Workstation Pro 17 |
| **İşletim Sistemi** | Windows Server 2025 Standard Evaluation |
| **Etki Alanı Adı** | `serifselen.local` |
| **DNS** | Otomatik olarak kurulmuştur |
| **Lisans** | Evaluation (180 gün) |

> 📝 **Bu doküman eğitim ve test ortamları için hazırlanmıştır. Üretimde lisanslı yazılım ve güvenlik önlemleri kullanılmalıdır.**
