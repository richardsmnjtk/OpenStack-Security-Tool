# OpenStack Security Tool

This script is a pentest tool that quickly detects and reports **potential security risks** in your OpenStack environments. It generates reports in both **HTML** and **JSON** format, providing a comprehensive scan down to management ports. You can easily install and use it by following the steps below.

<img width="823" alt="image" src="https://github.com/user-attachments/assets/c2099a30-7c6d-4c7c-947b-a49597b0b43e" />

---

## Features


- You can see and review all the details and features of the script in the blog post below!

https://mertcankondur.medium.com/openstack-from-a-penetration-tester-perspective-part-3-408bb334964a

---

## Installation

1. **Download Script** 
   ```bash
   git clone https://github.com/username/openstack-security-tool.git
   cd openstack-security-tool
   pip install -r requirements.txt

2. **Adding OpenStack RC File as a Source**
   ```bash
   source admin-openrc.sh
   ```

This command is required for the script to access OpenStack with admin privileges. You can download the ".sh" file as in the screenshot below by entering the Region where you want to perform the test with the admin account.

<img width="1720" alt="image" src="https://github.com/user-attachments/assets/75ccb2de-7c84-4ead-8712-3fabbb2870b3" />

 ---

## Usage

Basic Operation Example:
```bash
python tool.py --report-file report.html --json-report --threads 10
```
--report-file: The file to save the HTML report.

--json-report: It also generates a report (report.json) in JSON format.

--threads: Number of threads to use for parallel queries.

After the script runs, you can review the resulting HTML report (e.g. report.html) or JSON report (report.json) to see your findings at the "critical", "high", "medium", "low" levels.

## Contribution

Pull request veya issue açarak katkı sağlayabilirsiniz.

## Contact

Sorularınız veya önerileriniz için GitHub üzerinde bir issue açabilir, aşağıdaki mail adresimden veya Linkedin üzerinden iletişime geçebilirsiniz. Ayrıca büyük katkılar ve kod değişiklikleri için pull request açmaktan çekinmeyin.

- mertcann.kondur@gmail.com
- https://www.linkedin.com/in/mertcankondur/

