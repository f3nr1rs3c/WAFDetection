
🚀 **WAF Detection Tool**, bir web sitesinde **Web Application Firewall (WAF)** olup olmadığını hızlı bir şekilde tespit etmek için geliştirilmiş basit ama etkili bir Python aracıdır.

HTTP yanıt **header**, **server bilgisi** ve **response content** analiz edilerek yaygın WAF çözümleri tespit edilir.

Bu araç özellikle:

- 🔎 **Pentesterlar**
- 🛡️ **Bug Bounty araştırmacıları**
- 🧑‍💻 **Cybersecurity öğrencileri**

için hızlı bir **reconnaissance aracı** olarak kullanılabilir.

---

# ⚡ Özellikler

- ✨ Basit ve hızlı kullanım
- 🔍 HTTP header analizi
- 🧠 Response içerik analizi
- 🎨 Terminal banner (pyfiglet)
- 🌈 Renkli terminal çıktısı
- 🐍 Python tabanlı ve kolay genişletilebilir

---

# 🛡️ Desteklenen WAF Sistemleri

Tool şu WAF çözümlerini tespit edebilir:

- ☁️ **Cloudflare**
- 🌐 **Akamai**
- ☁️ **AWS WAF**
- 🛡️ **Incapsula**
- 🔐 **Sucuri**
- 🔍 **ModSecurity**
- 🏢 **F5 BIG-IP**
- ⚔️ **DDoS-GUARD**

Yeni WAF imzaları kolayca eklenebilir.

---

# 📦 Kurulum

Gerekli Python kütüphanelerini yükleyin:

```bash
pip install requests pyfiglet colorama
