# OpenStack Security Tool

Bu script, OpenStack ortamlarınızda **potansiyel güvenlik risklerini** hızla tespit edip raporlayan bir pentest aracıdır. Hem **HTML** hem de **JSON** formatında raporlar üreterek yönetim portlarına kadar kapsamlı bir tarama sağlar. Aşağıdaki adımları izleyerek kolayca kurabilir ve kullanabilirsiniz.

<img width="823" alt="image" src="https://github.com/user-attachments/assets/c2099a30-7c6d-4c7c-947b-a49597b0b43e" />

---

## İçindekiler
1. [Özellikler](#özellikler)
2. [Kurulum](#kurulum)
3. [Kullanım](#kullanım)
4. [Katkıda Bulunma](#katkıda-bulunma)
5. [Destek ve İletişim](#destek-ve-iletişim)

---

## Özellikler


- Scriptle ilgili tüm detayları ve özelliklerini aşağıdaki blog yazısında görebilir ve inceleyebilirsiniz!

https://mertcankondur.medium.com/openstack-from-a-penetration-tester-perspective-part-3-408bb334964a

---

## Kurulum

1. **Depoyu Klonlayın veya İndirin**  
   ```bash
   git clone https://github.com/username/openstack-security-tool.git
   cd openstack-security-tool
   pip install -r requirements.txt

2. **OpenStack RC Dosyasını Kaynak Olarak Eklemek**
   ```bash
   source admin-openrc.sh
   ```

Bu komut, script’in OpenStack’e admin yetkileriyle erişebilmesi için gereklidir.

 ---

## Kullanım

Temel Çalıştırma Örneği:
```bash
python openstack_security_tool.py --report-file report.html --json-report --threads 10
```
--report-file: HTML raporunun kaydedileceği dosya.

--json-report: Ek olarak JSON formatında bir rapor (report.json) da oluşturur.

--threads 10: Paralel sorgular için kullanılacak iş parçacığı sayısı.

Script çalıştıktan sonra, oluşan HTML raporu (örn. report.html) veya JSON raporu (report.json) inceleyerek “critical”, “high”, “medium”, “low” seviyelerindeki bulgularınızı görebilirsiniz.

## Katkıda Bulunma

Pull request veya issue açarak katkı sağlayabilirsiniz.

## Destek ve İletişim

Sorularınız veya önerileriniz için GitHub üzerinde bir issue açabilir ya da mertcann.kondur@gmail.com adresinden iletişime geçebilirsiniz. Ayrıca büyük katkılar ve kod değişiklikleri için pull request açmaktan çekinmeyin.

