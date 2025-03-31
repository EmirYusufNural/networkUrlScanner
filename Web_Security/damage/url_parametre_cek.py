from urllib.parse import urlparse, parse_qs

# URL'yi parçalamak için fonksiyon
def url_parametreleri_cek(url):
    # URL'yi ayrıştır
    parsed_url = urlparse(url)
    
    # Query kısmını al (parametreler buradadır)
    query_params = parse_qs(parsed_url.query)

    # Parametreleri yazdır
    print("Bulunan GET parametreleri:")
    for param, value in query_params.items():
        print(f"  {param} = {value}")

# Deneme URL'si
test_url = "https://example.com/search?q=python&lang=en"
url_parametreleri_cek(test_url)
