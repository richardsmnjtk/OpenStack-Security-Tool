# OpenStack Security Tool

Bu script, OpenStack ortamlarınızda **potansiyel güvenlik risklerini** hızla tespit edip raporlayan bir pentest aracıdır. Hem **HTML** hem de **JSON** formatında raporlar üreterek yönetim portlarına kadar kapsamlı bir tarama sağlar. Aşağıdaki adımları izleyerek kolayca kurabilir ve kullanabilirsiniz.

---

## İçindekiler
1. [Özellikler](#özellikler)
2. [Kurulum](#kurulum)
3. [Kullanım](#kullanım)
4. [Örnek config.json](#örnek-configjson)
5. [Çıktı Örnekleri](#çıktı-örnekleri)
6. [Tek Dosyada Bağımlılıklar (requirements)](#tek-dosyada-bağımlılıklar-requirements)
7. [Katkıda Bulunma](#katkıda-bulunma)
8. [Lisans](#lisans)
9. [Destek ve İletişim](#destek-ve-iletişim)

---

## Özellikler

- **Hassas Veri Tespiti**  
  Metadatalarda `password`, `secret_key`, `private_key` gibi kelimeleri arar; `BEGIN RSA PRIVATE KEY` gibi kalıpları tespit ederse kritik seviyede uyarılar verir.
- **Security Group Denetimleri**  
  `0.0.0.0/0` ile ANY protokol veya yönetim portlarına tam açık erişim gibi yüksek riskli durumları listeleyip raporlar.
- **Outdated/EOL İmaj Kontrolleri**  
  “trusty”, “14.04”, “eol” ve “endoflife” kalıpları içeren imajları kritik olarak işaretler.
- **Public Bucket Analizi**  
  Public read veya write access gibi durumları yüksek/kritik risk seviyesinde bulgu olarak gösterir.
- **Admin Kullanıcı Kontrolü**  
  Belirli bir “allowed admin users” listesiyle karşılaştırıp, bu listede olmayan admin kullanıcılar için `high` seviye uyarı, kullanıcı adında `test` geçiyorsa `critical` uyarı üretir.

---

## Kurulum

1. **Depoyu Klonlayın veya İndirin**  
   ```bash
   git clone https://github.com/username/openstack-security-tool.git
   cd openstack-security-tool
