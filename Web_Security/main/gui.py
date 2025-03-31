import json
import csv
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from bs4 import BeautifulSoup

# Form verilerini almak için fonksiyon
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

# Verileri kaydetme işlemi
def veri_kaydet(form_data, folder_path, file_formats):
    # Dosya formatlarına göre kaydetme işlemi
    if 'txt' in file_formats:
        with open(os.path.join(folder_path, "form_verileri.txt"), 'a') as file:
            for form in form_data:
                file.write(f"Form Action: {form['action']}\n")
                file.write(f"Form Method: {form['method']}\n")
                for input_tag in form['inputs']:
                    file.write(f"Input Name: {input_tag['name']}, Type: {input_tag['type']}, Placeholder: {input_tag['placeholder']}\n")
                for textarea_tag in form['textareas']:
                    file.write(f"Textarea Name: {textarea_tag['name']}, Placeholder: {textarea_tag['placeholder']}\n")
                file.write("\n" + "-"*20 + "\n")
    
    if 'json' in file_formats:
        with open(os.path.join(folder_path, "form_verileri.json"), 'w') as file:
            json.dump(form_data, file, indent=4)

    if 'csv' in file_formats:
        with open(os.path.join(folder_path, "form_verileri.csv"), 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Form Action', 'Form Method', 'Input Name', 'Input Type', 'Input Placeholder', 'Textarea Name', 'Textarea Placeholder'])

            for form in form_data:
                for input_tag in form['inputs']:
                    writer.writerow([form['action'], form['method'], input_tag['name'], input_tag['type'], input_tag['placeholder'], '', ''])
                for textarea_tag in form['textareas']:
                    writer.writerow([form['action'], form['method'], '', '', '', textarea_tag['name'], textarea_tag['placeholder']])


# URL ve dosya kaydetme kısmı
def url_al():
    # Tkinter arayüzü
    def open_url():
        url = url_entry.get()
        if url == 'q':
            root.quit()
            return
        url = url if url.startswith(("http://", "https://")) else "https://" + url  
        url = url if "www." in url else url.replace("https://", "https://www.")
        
        try:
            html = urlopen(url).read()
        except (URLError, HTTPError) as e: 
            messagebox.showerror("Hata", f"Siteye ulaşılamadı: {e}")
            return

        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        
        form_data_list = []  # Form verilerini tutacağımız liste
        for form in forms:
            form_data = form_verisi_olustur(form)
            form_data_list.append(form_data)
        
        # Kullanıcıya dosya kaydetme seçeneklerini sunma
        folder_name = filedialog.askdirectory(title="Klasör Seçin")
        if folder_name:
            # Seçilen dosya formatları
            file_formats = []
            if txt_var.get():
                file_formats.append('txt')
            if json_var.get():
                file_formats.append('json')
            if csv_var.get():
                file_formats.append('csv')
            
            if not file_formats:
                messagebox.showwarning("Uyarı", "En az bir dosya formatı seçmelisiniz!")
                return

            veri_kaydet(form_data_list, folder_name, file_formats)
            messagebox.showinfo("Başarılı", "Veriler başarıyla kaydedildi.")

    # Modernize edilmiş Tkinter GUI
    root = tk.Tk()
    root.title("Form Verisi Çekici")
    root.geometry("600x400")  # Genişlik ve yükseklik

    # Ana pencerede stil ekleme
    style = ttk.Style()
    style.configure('TButton', font=('Arial', 12), padding=10, relief="flat", background="#4CAF50", foreground="black")
    style.configure('TEntry', font=('Arial', 12), padding=10)
    style.configure('TLabel', font=('Arial', 14), background="#F0F0F0", foreground="#333")
    style.configure('TCombobox', font=('Arial', 12), padding=10)

    # Başlık ve açıklama
    title_label = ttk.Label(root, text="Web Form Verisi Çekici", anchor="center")
    title_label.pack(pady=10)

    description_label = ttk.Label(root, text="URL'yi girin ve veriyi kaydedin.", anchor="center")
    description_label.pack(pady=5)

    # URL girişi
    url_label = ttk.Label(root, text="URL Girin:", anchor="w")
    url_label.pack(padx=20, pady=5, anchor="w")

    url_entry = ttk.Entry(root, width=50)
    url_entry.pack(pady=10)

    # Format Seçim (Checkbox)
    format_label = ttk.Label(root, text="Kaydetme Formatını Seçin (txt, json, csv):")
    format_label.pack(padx=20, pady=5, anchor="w")
    
    txt_var = tk.BooleanVar()
    json_var = tk.BooleanVar()
    csv_var = tk.BooleanVar()

    txt_check = ttk.Checkbutton(root, text="txt", variable=txt_var)
    json_check = ttk.Checkbutton(root, text="json", variable=json_var)
    csv_check = ttk.Checkbutton(root, text="csv", variable=csv_var)

    txt_check.pack()
    json_check.pack()
    csv_check.pack()

    # Verileri çekme ve kaydetme butonu
    fetch_button = ttk.Button(root, text="Verileri Çek ve Kaydet", command=open_url)
    fetch_button.pack(pady=20)

    # Çıkış butonu
    exit_button = ttk.Button(root, text="Çıkış", command=root.quit)
    exit_button.pack(pady=10)

    root.mainloop()

# GUI'yi çalıştır
url_al()
