import re
import json
import csv
# Log məlumatları
log_data = """
192.168.1.10 - - [05/Dec/2024:10:15:45 +0000] "POST /login HTTP/1.1" 200 5320
192.168.1.11 - - [05/Dec/2024:10:16:50 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.15 - - [05/Dec/2024:10:17:02 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:18:10 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:19:30 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:20:45 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.16 - - [05/Dec/2024:10:21:03 +0000] "GET /home HTTP/1.1" 200 3020
"""

# Regex nümunəsi
pattern = r"(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] \"(\w+)"

# Məlumatları çıxarma
matches = re.findall(pattern, log_data)

# Nəticələri çap et
for match in matches:
    ip, date, method = match
    print(f"IP: {ip}, Tarix: {date}, HTTP Metodu: {method}")




# Log məlumatları
log_data = """
192.168.1.10 - - [05/Dec/2024:10:15:45 +0000] "POST /login HTTP/1.1" 200 5320
192.168.1.11 - - [05/Dec/2024:10:16:50 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.15 - - [05/Dec/2024:10:17:02 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:18:10 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:19:30 +0000] "POST /login HTTP/1.1" 401 2340
192.168.1.11 - - [05/Dec/2024:10:20:45 +0000] "POST /login HTTP/1.1" 401 2340
10.0.0.16 - - [05/Dec/2024:10:21:03 +0000] "GET /home HTTP/1.1" 200 3020
"""

# Regex nümunəsi
pattern = r"(\d+\.\d+\.\d+\.\d+) - - \[.*?\] \"(POST|GET|PUT|DELETE|PATCH|OPTIONS|HEAD).*?\" (\d+)"

# Məlumatları çıxarma
matches = re.findall(pattern, log_data)

# Uğursuz giriş cəhdlərini saymaq üçün lüğət
failed_attempts = {}
for match in matches:
    ip, method, status = match
    if status == "401":  # 401 uğursuz giriş statusudur
        if ip not in failed_attempts:
            failed_attempts[ip] = 0
        failed_attempts[ip] += 1

# 5-dən çox uğursuz giriş cəhdi olan IP-ləri tapmaq
suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > 5}

# Nəticələri JSON faylına yazmaq
with open("suspicious_ips.json", "w") as json_file:
    json.dump(suspicious_ips, json_file, indent=4)

# Çap etmək üçün
print("5-dən çox uğursuz giriş cəhdi olan IP-lər:")
for ip, count in suspicious_ips.items():
    print(f"IP: {ip}, Cəhd sayı: {count}")




# Regex nümunəsi
pattern = r"(\d+\.\d+\.\d+\.\d+) - - \[.*?\] \"(POST|GET|PUT|DELETE|PATCH|OPTIONS|HEAD).*?\" (\d+)"

# Məlumatları çıxarma
matches = re.findall(pattern, log_data)

# Uğursuz giriş cəhdlərini saymaq üçün lüğət
failed_attempts = {}
for match in matches:
    ip, method, status = match
    if status == "401":  # 401 uğursuz giriş statusudur
        if ip not in failed_attempts:
            failed_attempts[ip] = 0
        failed_attempts[ip] += 1

# Uğursuz giriş cəhdlərini fayla yazmaq
with open("failed_attempts.txt", "w", encoding="utf-8") as text_file:
    for ip, count in failed_attempts.items():
        text_file.write(f"IP: {ip}, Cəhd sayı: {count}\n")

# Çap etmək üçün
print("Uğursuz giriş cəhdləri mətn faylına yazıldı:")
for ip, count in failed_attempts.items():
    print(f"IP: {ip}, Cəhd sayı: {count}")



pattern = r"(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] \"(POST|GET|PUT|DELETE|PATCH|OPTIONS|HEAD).*?\" (\d+)"

# Məlumatları çıxarma
matches = re.findall(pattern, log_data)

# CSV yazmaq üçün məlumatları formatlaşdırmaq
rows = []
for match in matches:
    ip, date, method, status = match
    failed_attempt = 1 if status == "401" else 0  # 401 statusu uğursuz giriş cəhdi kimi qeyd olunur
    rows.append([ip, date, method, failed_attempt])

# CSV faylına yazmaq
with open("log_data.csv", "w", newline="", encoding="utf-8") as csvfile:
    csv_writer = csv.writer(csvfile)
    # Başlıqlar
    csv_writer.writerow(["IP ünvanı", "Tarix", "HTTP metodu", "Uğursuz cəhdlər"])
    # Məlumat
    csv_writer.writerows(rows)

print("CSV faylı uğurla yaradıldı: log_data.csv")



threat_intel_ips = [
    "192.168.1.11",
    "10.0.0.15"
]

# Regex nümunəsi ilə loglardan IP ünvanlarını çıxar
pattern = r"(\d+\.\d+\.\d+\.\d+)"
log_ips = re.findall(pattern, log_data)

# Təhlükəli IP-lərin loglardakı uyğunluğunu yoxla
matched_ips = [ip for ip in log_ips if ip in threat_intel_ips]

# Təhdid məlumatlarını JSON formatında saxla
threat_data = {"threat_ips": list(set(matched_ips))}

# JSON faylına yaz
with open("threat_ips.json", "w", encoding="utf-8") as json_file:
    json.dump(threat_data, json_file, indent=4)

print("Təhdid kəşfiyyatı ilə uyğun gələn IP ünvanları JSON faylına yazıldı.")
