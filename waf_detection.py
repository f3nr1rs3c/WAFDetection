import requests
from pyfiglet import Figlet
from colorama import init, Fore
import os
from os import system
from time import sleep

init()

def clear_screen():
    system("cls" if os.name == "nt" else "clear")

def print_banner():
    figlet = Figlet(font='slant')
    print(Fore.BLUE + figlet.renderText('Waf Detection') + Fore.RESET)

clear_screen()
print_banner()

# Waf Türleri
waf_signatures = {
    'Cloudflare': {
        'Server': ['cloudflare'],
        'Other Indicators': ['captcha', '403 Forbidden']
    },
    'Akamai': {
        'Server': ['AkamaiGHost'],
        'Headers': ['X-Akamai-Session-ID']
    },
    'AWS WAF': {
        'Server': ['AWS'],
        'Headers': ['X-Amz-Cf-Id']
    },
    'Incapsula': {
        'Server': ['Incapsula'],
        'Headers': ['X-CDN']
    },
    'Sucuri': {
        'Headers': ['X-Sucuri-ID']
    },
    'ModSecurity': {
        'Headers': ['Mod_Security', 'ModSecurity'],
        'Other Indicators': ['security alert', '403 Forbidden']
    },
    'F5 BIG-IP': {
        'Server': ['BigIP', 'F5 Networks'],
        'Headers': ['X-WAF-Status']
    },
    'DDoS-GUARD': {
        'Server': ['DDoS-GUARD']
    }
}

# Tespit fonksiyonu
def detect_waf(url):
    try:
        response = requests.get(url)
        headers = response.headers
        
        detected_waf = []

        # WAF imzalarını kontrol ediyoruz.
        for waf_name, waf_criteria in waf_signatures.items():
            # Server başlığı kontrolü
            if 'Server' in waf_criteria and 'Server' in headers:
                for signature in waf_criteria['Server']:
                    if signature.lower() in headers['Server'].lower():
                        detected_waf.append(waf_name)
                        break
            
            # Headers kontrolü
            if 'Headers' in waf_criteria:
                for header in waf_criteria['Headers']:
                    if header in headers:
                        detected_waf.append(waf_name)
                        break
            
            # Diğer belirtiler (Yanıt içeriğinde) kontrolü
            if 'Other Indicators' in waf_criteria:
                for indicator in waf_criteria['Other Indicators']:
                    if indicator.lower() in response.text.lower():
                        detected_waf.append(waf_name)
                        break

        # Sonuçları döndürüyoruz
        if detected_waf:
            print(Fore.GREEN + f"{url} waf detected: {', '.join(set(detected_waf))}" + Fore.RESET)
        else:
            print(Fore.YELLOW + f"{url} no WAF detected at the address." + Fore.RESET)
    
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"An error occurred during the request: {e}" + Fore.RESET)

# Kullanıcıdan URL alıyoruz.
if __name__ == "__main__":
    target_url = input(Fore.WHITE + "Please enter the website URL you want to search (including http/https): " + Fore.RESET)
    detect_waf(target_url)
