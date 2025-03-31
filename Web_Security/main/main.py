import json
import csv
import os
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from bs4 import BeautifulSoup

# 📌 GET Parametrelerini Çekme Fonksiyonu
def url_parametreleri_cek(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    param_listesi = []
    
    for param, value in query_params.items():
        param_listesi.append({'parametre': param, 'deger': value})
    
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
    with open(os.path.join(folder_path, "veriler.txt"), 'a') as file:
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
    with open(os.path.join(folder_path, "veriler.json"), 'w') as file:
        json.dump(data, file, indent=4)

# 📌 Verileri CSV Olarak Kaydetme
def veri_kaydet_csv(form_data, param_data, folder_path):
    with open(os.path.join(folder_path, "veriler.csv"), 'w', newline='') as file:
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

# 📌 URL'den Form ve Parametreleri Çekme
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

        # 📌 Dosya formatını belirle
        folder_path, file_formats = dosya_secim()

        # 📌 Verileri kaydet
        if 'txt' in file_formats:
            veri_kaydet_txt(form_data_list, param_data_list, folder_path)
        if 'json' in file_formats:
            veri_kaydet_json(form_data_list, param_data_list, folder_path)
        if 'csv' in file_formats:
            veri_kaydet_csv(form_data_list, param_data_list, folder_path)

# 📌 Fonksiyonu Çalıştır
url_al()
