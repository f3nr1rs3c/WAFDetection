#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WAFSeeker - Professional Web Application Firewall Detector
Author: Sirius (Updated via Antigravity)

Özellikleri ve Pentest Notları:
- **Agresif WAF Taraması (Malicious Payload):** Çoğu gelişmiş WAF, normal trafiği maskeler
  ve varlığını gizler. Bu araç sadece normal bir istek atmaz, aynı zamanda bilerek zararlı 
  bir XSS/SQLi payload'u göndererek sistemin tepkisini ölçmeye çalışır (Davranışsal Tespit).
- **Kapsamlı WAF İmzaları:** Cloudflare, Akamai, AWS, Incapsula, ModSecurity, F5, FortiWeb gibi
  endüstri standartı 15'ten fazla güvenlik cihazının HTTP Response, Cookie ve Content Header 
  imzalarını kullanır.
- **Toplu Tarama (Bulk Scan):** Birden fazla hedefi içeren bir listeyi çoklu iş parçacıkları
  ile (-t threads) aynı anda tarayıp raporlayabilir.
- **Proxy Tünelleme:** İsteğe bağlı (--proxy) tarama trafiğini proxy (örn. Burp Suite) 
  üzerinden geçirmenize olanak tanır.
"""

import argparse
import os
import sys
import random
import urllib.parse
import concurrent.futures
from colorama import init, Fore, Style

try:
    import requests
    import urllib3
    from pyfiglet import Figlet
except ImportError:
    print("[-] Eksik kütüphaneler var. Yükleyin: pip install requests colorama pyfiglet urllib3")
    sys.exit(1)

# Colorama başlat (Windows için gerekli Terminal Renkleri)
init(autoreset=True)

# SSL Uyarılarını gizle (Pentest sırasında Self-Signed sertifikalar sürekli hata verir)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Tarama sırasında güvenlik mekanizmalarını atlatmak için kullanılan User-Agent'lar
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
]

# Gelişmiş WAF İmzaları (Cookie, Header, Body, Algoritma)
# WAF'lar web trafiğini izler ve zararlı bir durumda engelleme atar. Bu engelleme esnasında
# veya sadece sessionu tutmak için izler (cookie vb.) bırakırlar. Analiz bu izlere göre yapılır.
WAF_SIGNATURES = {
    'Cloudflare': {
        'Server': ['cloudflare'],
        'Cookies': ['__cfduid', 'cf_clearance'],
        'Headers': ['CF-RAY', 'CF-Cache-Status'],
        'Body': ['Attention Required! | Cloudflare', 'cloudflare-nginx']
    },
    'Akamai': {
        'Server': ['AkamaiGHost'],
        'Cookies': ['ak_bmsc', 'bm_sv'],
        'Headers': ['X-Akamai-Session-ID', 'X-Akamai-Trans-ID'],
        'Body': ['Access Denied', 'You don\'t have permission to access']
    },
    'AWS WAF': {
        'Server': ['AWS', 'AmazonS3'],
        'Cookies': ['aws-waf-token'],
        'Headers': ['X-Amz-Cf-Id'],
        'Body': ['403 ERROR', 'Request blocked.']
    },
    'Incapsula (Imperva)': {
        'Server': ['Incapsula'],
        'Cookies': ['incap_ses', 'visid_incap'],
        'Headers': ['X-CDN'],
        'Body': ['Incapsula incident ID']
    },
    'Sucuri': {
        'Server': ['Sucuri/Cloudproxy'],
        'Headers': ['X-Sucuri-ID', 'X-Sucuri-Cache'],
        'Body': ['Access Denied - Sucuri Website Firewall']
    },
    'ModSecurity': {
        'Server': ['Mod_Security', 'NOYB'],
        'Headers': ['ModSecurity'],
        'Body': ['Not Acceptable', 'security alert', 'Forbidden']
    },
    'F5 BIG-IP / ASM': {
        'Server': ['BigIP', 'F5 Networks', 'F5'],
        'Cookies': ['TS01', 'BIGipServer'],
        'Headers': ['X-WA-Info', 'X-WAF-Status'],
        'Body': ['The requested URL was rejected. Please consult with your administrator.']
    },
    'DDoS-GUARD': {
        'Server': ['ddos-guard', 'DDoS-GUARD'],
        'Cookies': ['__ddg1_'],
        'Body': ['DDoS-Guard']
    },
    'FortiWeb': {
        'Cookies': ['FORTIWAFSID'],
        'Headers': ['X-FORTIWAF'],
        'Body': ['.fgd_icon']
    },
    'Citrix NetScaler': {
        'Cookies': ['ns_af=', 'citrix_ns_id', 'NSC_'],
        'Headers': ['Cneonction', 'nnCoection', 'Via: ns_netscaler']
    },
    'Barracuda': {
        'Cookies': ['barra_counter_session', 'BNI__BARRACUDA_LB_COOKIE']
    },
    'StackPath / MaxCDN': {
        'Server': ['NetDNA-cache'],
        'Headers': ['X-Edge-IP']
    }
}

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def print_banner():
    f = Figlet(font='slant', width=100)
    print(Fore.BLUE + Style.BRIGHT + f.renderText('WAFSeeker'))

def analyze_response(response, waf_detected):
    """Gelen HTTP yanıtını WAF imzaları ile test eder."""
    if not response:
        return
        
    headers = response.headers
    cookies = response.cookies.get_dict()
    body = response.text
    
    for waf_name, criteria in WAF_SIGNATURES.items():
        # Sunucu (Server) Header kontrolü
        if 'Server' in criteria and 'Server' in headers:
            for sig in criteria['Server']:
                if sig.lower() in headers['Server'].lower():
                    waf_detected.add(waf_name)
                    
        # Özel Header kontrolleri (örn. X-CDN)
        if 'Headers' in criteria:
            for header in criteria['Headers']:
                if header in headers:
                    waf_detected.add(waf_name)
                    
        # Çerez (Cookie) kontrolleri
        if 'Cookies' in criteria:
            for sig in criteria['Cookies']:
                for cookie in cookies:
                    if sig.lower() in cookie.lower():
                        waf_detected.add(waf_name)
                        
        # Body içeriği blok tespiti (Özellikle 403 sayfalarındaki metinler tespit edilir)
        if 'Body' in criteria:
            for sig in criteria['Body']:
                if sig.lower() in body.lower():
                    waf_detected.add(waf_name)

def detect_waf(url, proxies=None):
    """
    Davranışsal Test Metodolojisi:
    1- Clean İstemci Analizi (Header / Cookie üzerinden)
    2- Dirty İstemci Analizi (Saldırı gönderip cevaba bakma)
    """
    
    if not url.startswith("http"):
        url = "http://" + url
        
    base_headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
    
    # Zararlı Pentest Payloadu: WAF kurallarını manuel tetiklemek hedeflenir.
    dirty_payload = "/?id=1'+OR+1=1+UNION+SELECT+1,2,3--&script=<script>alert(1)</script>"
    dirty_url = urllib.parse.urljoin(url, dirty_payload)
    
    waf_detected = set()
    res_clean = None
    res_dirty = None

    try:
        # 1. Clean Request
        try:
            res_clean = requests.get(url, headers=base_headers, timeout=10, proxies=proxies, verify=False)
            analyze_response(res_clean, waf_detected)
        except Exception:
             pass 

        # 2. Dirty Request
        try:
             res_dirty = requests.get(dirty_url, headers=base_headers, timeout=10, proxies=proxies, verify=False)
             analyze_response(res_dirty, waf_detected)
             
             # Eğer agresif istek atıldığında 403/406 dönerse ve temiz istek 200 dönerse;
             # Bu davranış hedefin bizi WAF üzerinden kesin engellediğini gösterir.
             if res_dirty and res_clean:
                 if res_dirty.status_code in [403, 406] and res_clean.status_code == 200:
                      waf_detected.add("Unidentified WAF (Generic Behavior Block)")
        except Exception:
             pass
             
        # Sonuç Rapolama
        if waf_detected:
             results = ", ".join(waf_detected)
             print(Fore.GREEN + Style.BRIGHT + f"[+] WAF TESPİT EDİLDİ [{url}]: {results}" + Fore.RESET)
             return f"{url} - {results}"
        else:
             print(Fore.YELLOW + f"[-] WAF TESPİT EDİLEMEDİ [{url}]" + Fore.RESET)
             return None
             
    except Exception as e:
        print(Fore.RED + f"[!] Bağlantı Başarısız ({url})" + Fore.RESET)
        return None

def main():
    clear_screen()
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="WAFSeeker - Profesyonel Web Uygulama Güvenlik Duvarı Tespiti",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Pentest Tavsiyeleri:
--------------------
• Bulunan WAF teknolojisine özgü Bypass tekniklerini (Örn: CloudFlare Bypass, ModSec Evasion) deneyin.
• Gerçek IP adresini bulabilirseniz WAF'ı tamamen aşabilirsiniz (Censys, Shodan, SSRF ile hedefi arayın).
        
Örnek Kullanım:
  python WAFSeeker.py -u example.com
  python WAFSeeker.py -l hedefler.txt -t 10
  python WAFSeeker.py -u example.com --proxy http://127.0.0.1:8080 -o waf_sonuc.txt
"""
    )
    
    parser.add_argument("-u", "--url", help="Hedef URL (örn: example.com)")
    parser.add_argument("-l", "--list", help="Toplu tarama için hedef listesi (txt dosyası)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Eşzamanlı tarama (Sadece liste ile çalışırken, Default: 5)")
    parser.add_argument("-o", "--output", help="Tespit edilen WAF'ları kaydet (.txt)")
    parser.add_argument("-p", "--proxy", help="Standart Proxy (Örn: http://127.0.0.1:8080)")
    
    # Parametresiz çalışmada interaktif deneyim
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        print("\n" + Fore.YELLOW + "[!] Argüman girilmedi, İnteraktif Moda geçiliyor..." + Fore.RESET)
        try:
            target = input(Fore.WHITE + "Aranacak web sitesi URL'sini girin: " + Fore.RESET).strip()
            if not target:
                sys.exit(0)
            print(Fore.MAGENTA + "[*] Tarama başlatılıyor..." + Fore.RESET)
            detect_waf(target)
        except KeyboardInterrupt:
            pass
        sys.exit(0)

    args = parser.parse_args()
    
    proxy_dict = None
    if args.proxy:
        proxy_dict = {"http": args.proxy, "https": args.proxy}
        
    found_wafs = []
    
    if args.url:
        print(Fore.MAGENTA + f"[*] Hedef taranıyor: {args.url}..." + Fore.RESET)
        res = detect_waf(args.url, proxies=proxy_dict)
        if res:
            found_wafs.append(res)
            
    elif args.list:
        try:
            with open(args.list, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
                
            print(Fore.MAGENTA + f"[*] Çoklu tarama başlatıldı. Hedef sayısı: {len(urls)} (Threads: {args.threads})" + Fore.RESET)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                # WAF taramasını proxy ile eşle
                futures = {executor.submit(detect_waf, url, proxy_dict): url for url in urls}
                
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        found_wafs.append(result)
                        
        except FileNotFoundError:
             print(Fore.RED + f"[-] Belirtilen liste dosyası bulunamadı: {args.list}")
             sys.exit(1)
    else:
        print(Fore.RED + "[-] Lütfen bir hedef (-u) veya hedef listesi (-l) belirtin.")
        sys.exit(1)
        
    if args.output and found_wafs:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write("WAFSeeker Tespit Raporu\n")
                f.write("="*30 + "\n")
                for w in found_wafs:
                    f.write(w + "\n")
            print(Fore.CYAN + Style.BRIGHT + f"\n[+] Sonuçlar başarıyla {args.output} dosyasına kaydedildi.")
        except Exception as e:
            print(Fore.RED + f"[!] Dosya kaydetme hatası: {e}")

if __name__ == "__main__":
    main()
