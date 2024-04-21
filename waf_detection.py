from scapy.all import ARP, Ether, srp
import os
import subprocess
from pyfiglet import Figlet
from colorama import init, Fore

# Initialize Colorama Başlatıldı
init()

def clear_screen():
    os.system("clear")

def print_banner():
    f = Figlet(font='slant', width=100)
    print(Fore.MAGENTA + f.renderText('Firewall Detection'))
    print(Fore.RED + "                      | - |  By : F3NR1R - Cyber Security | - |         " + Fore.RESET)

def detect_waf(target_url):
    try:
        # wafw00f komutunu çağırarak hedef URL üzerinde WAF tespiti yap
        result = subprocess.check_output(["wafw00f", target_url], universal_newlines=True)
        
        # wafw00f çıktısını ekrana yazdır
        print(result)
        
    except subprocess.CalledProcessError as e:
        # wafw00f çağrısı başarısız olduğunda hata mesajını yazdır
        print("WAF detection failed:", e)

# Ana program
def main():
    print_banner()  # Bannerı ekrana yazdır
    target_url = input(Fore.BLUE + "Enter Target URL: " + Fore.RESET)
    detect_waf(target_url)

if __name__ == "__main__":
    main()
