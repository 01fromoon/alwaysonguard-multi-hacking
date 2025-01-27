import subprocess
import socket
import requests
import time
from colorama import init, Fore, Style


def run_command(command):
    try:
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while executing command: {command}\nError: {e}")

def show_main_menu():
    print("""
    _____  .__                              ________           ________                       .___
    /  _  \ |  |__  _  _______  ___.__. _____\_____  \   ____  /  _____/ __ _______ _______  __| _/
    /  /_\  \|  |\ \/ \/ /\__  \<   |  |/  ___//   |   \ /    \/   \  ___|  |  \__  \\_  __ \/ __ | 
    /    |    \  |_\     /  / __ \\___  |\___ \/    |    \   |  \    \_\  \  |  // __ \|  | \/ /_/ | 
    \____|__  /____/\/\_/  (____  / ____/____  >_______  /___|  /\______  /____/(____  /__|  \____ | 
            \/                  \/\/         \/        \/     \/        \/           \/           \/ 
                                                            Multi Hacking Tool / By 01fromoon
   """)
    


    print("[1] AnonSurf")
    print("[2] Information Gathering")
    print("[3] SQL Injection Tools.")
    print("[4] Wireless Attack")
    print("[5] Password Attacks")
    print("[6] Phishing Tool")
    print("[7] Web Attack Tool")
    print("[8] Post exploitation")
    print("[9] Forensic Tools")
    print("[10] Payload Creator")
    print("[11] Router Exploit")
    print("[12] Wifi Jamming")
    print("[13] SocialMedia Attack")
    print("[14] SocialMedia Finder")
    print("[15] Android Hack")
    print("[16] Port Forwarding")
    print("[17] Other Tools")
    print("[18] Exit")

def option_1():
    while True:
        print("\nAnonSurf Options:")
        print("[1] Anonymously surf")
        print("[2] Multitor")
        print("[3] Back") 
        
        choice = input("Select an option (1-3): ")
        
        if choice == '1':
            print("You have selected to surf anonymously.")
            run_command("sudo git clone https://github.com/Und3rf10w/kali-anonsurf.git")
            run_command("cd kali-anonsurf && sudo ./installer.sh && cd .. && sudo rm -r kali-anonsurf")
            print("Anonsurf has been installed successfully.")
            run_command("sudo anonsurf start")
        elif choice == '2':
            print("You have selected Multitor.")
            run_command("sudo git clone https://github.com/trimstray/multitor.git")
            run_command("cd multitor; sudo bash setup.sh install")
            print("Multitor has been installed successfully.")
            run_command("multitor --init 2 --user debian-tor --socks-port 9000 --control-port 9900 --proxy privoxy --haproxy")
        elif choice == '3':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.") 

def option_2():
    while True:
        print("\nInformation Gathering Options:")
        print("[1] Nmap")
        print("[2] Dracnmap")
        print("[3] Port Scanning")
        print("[4] Host To IP")
        print("[5] Xerosploit")
        print("[6] IsItDown (check website Down/Up)")
        print("[7] Coming Soon..")
        print("[8] Back to Main Menu")
        
        choice = input("Select an option (1-8): ")
        
        if choice == '1':
            print("You have selected Nmap.")
            run_command("sudo git clone https://github.com/nmap/nmap.git")
            run_command("sudo chmod -R 755 nmap && cd nmap && sudo ./configure && make && sudo make install")
            print("Nmap has been installed successfully.")
        elif choice == '2':
            print("You have selected Dracnmap.")
            try:
                run_command("sudo git clone https://github.com/Screetsec/Dracnmap.git")
                run_command("cd Dracnmap && chmod +x dracnmap-v2.2-dracOs.sh dracnmap-v2.2.sh")
                run_command("cd Dracnmap; sudo ./dracnmap-v2.2.sh")
                print("Dracnmap has been installed successfully.")
            except subprocess.CalledProcessError as e:
                print(f"An error occurred: {e}")
        elif choice == '3':
            print("You have selected Port Scanning.")
            target_ip = input("Please enter the target IP address: ")
            run_command(f"sudo nmap -O -Pn {target_ip}")
            print(f"Port scanning completed for {target_ip}.")
        elif choice == '4':
            print("You have selected Host To IP.")
            domain = input("Please enter the domain name: ")
            try:
                ip_address = socket.gethostbyname(domain)
                print(f"The IP address of {domain} is {ip_address}.")
            except socket.gaierror:
                print("Could not resolve the domain. Please check the domain name.")
        elif choice == '5':
            print("You have selected Xerosploit.")
            try:
                run_command("git clone https://github.com/LionSec/xerosploit.git")
                run_command("cd xerosploit")
                run_command("sudo python install.py")
                run_command("sudo xerosploit")
            except subprocess.CalledProcessError as e:
                print(f"An error occurred while installing Xerosploit: {e}")
        elif choice == '6':
            print("You have selected IsItDown.")
            website = input("Please enter the website URL (e.g., example.com): ")
            try:
                response = requests.get(f"http://{website}")
                if response.status_code == 200:
                    print(f"The website {website} is up and running.")
                else:
                    print(f"The website {website} is down or not reachable.")
            except requests.ConnectionError:
                print(f"The website {website} is down or not reachable.")
        elif choice == '7':
            print("Coming Soon...")
            # İlgili işlemleri burada gerçekleştirin
        elif choice == '8':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_3():
    while True:
        print("\nSQL Injection Tools:")
        print("[1] Leviathan")
        print("[2] Explo")
        print("[3] Sqlmap")
        print("[4] Back to Main Menu")
        
        choice = input("Select an option (1-4): ")
        
        if choice == '1':
            print("You have selected Leviathan.")
            # Leviathan ile ilgili komutları buraya ekleyin
        elif choice == '2':
            print("You have selected Explo.")
            # Explo ile ilgili komutları buraya ekleyin
        elif choice == '3':
            print("You have selected Sqlmap.")
            print("Installing Sqlmap...")
            run_command("sudo apt install sqlmap -y")  # Sqlmap'ı yükle
            print("Sqlmap has been installed successfully.")
            print("Starting Sqlmap...")
            run_command("sqlmap --help")  # Sqlmap yardımını göster
        elif choice == '4':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_4():
    while True:
        print("\nWireless Attack Options:")
        print("[1] Wifite")
        print("[2] Pixiewps")
        print("[3] Airgeddon")
        print("[4] Ettercap")
        print("[5] Bettercap")
        print("[6] Exit")
        
        choice = input("Select an option (1-6): ")
        
        if choice == '1':
            print("You have selected Wifite.")
            print("Installing Wifite...")
            run_command("sudo apt install wifite -y")  # Wifite'i yükle
            print("Wifite has been installed successfully.")
            print("Displaying Wifite help...")
            run_command("wifite --help")  # Wifite yardımını göster
            print("Starting Wifite...")
            run_command("wifite")
        elif choice == '2':
            print("You have selected Pixiewps.")
            print("Installing Pixiewps...")
            run_command("sudo apt update")
            run_command("sudo apt install git -y")
            run_command("sudo apt install build-essential -y")
            run_command("sudo apt install aircrack-ng -y")
            run_command("sudo apt install libssl-dev -y")
            run_command("git clone https://github.com/wiire/pixiewps.git")
            run_command("cd pixiewps")
            run_command("make")
            print("Starting Pixiewps...")
            run_command("sudo ./pixiewps")  # Pixiewps'i başlat
        elif choice == '3':
            print("You have selected Airgeddon.")
            print("Installing Airgeddon...")
            run_command("sudo apt install git -y")
            run_command("sudo apt install aircrack-ng -y")
            run_command("sudo apt install iw -y")
            run_command("sudo apt install dnsmasq -y")
            run_command("sudo apt install lighttpd -y")
            run_command("sudo apt install php -y")
            run_command("git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git")
            run_command("cd airgeddon")
            print("Starting Airgeddon...")
            run_command("sudo bash airgeddon.sh")  # Airgeddon'u başlat
        elif choice == '4':
            print("You have selected Ettercap.")
            print("Installing Ettercap...")
            run_command("sudo apt install ettercap-graphical -y")  # Ettercap'ı yükle
            print("Starting Ettercap...")
            run_command("sudo ettercap -G")  # Ettercap'ı başlat
        elif choice == '5':
            print("You have selected Bettercap.")
            print("Installing Bettercap...")
            run_command("sudo apt install bettercap -y")  # Bettercap'ı yükle
            print("Displaying Bettercap help...")
            run_command("bettercap --help")  # Bettercap yardımını göster
            print("Starting Bettercap...")
            run_command("sudo bettercap")  # Bettercap'ı başlat
        elif choice == '6':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_5():
    print("Password Attacks selected.")

def option_6():
    while True:
        print("\nPhishing Tool Options:")
        print("[1] Pyphisher")
        print("[2] AdvPhishing")
        print("[3] HiddenEye")
        print("[4] zphisher")
        print("[5] Back to Main Menu")
        
        choice = input("Select an option (1-5): ")
        
        if choice == '1':
            print("You have selected Pyphisher.")
            run_command("git clone https://github.com/UndeadSec/Pyphisher.git")
            print("Pyphisher has been cloned successfully.")
            run_command("cd Pyphisher && chmod +x pyphisher.py")
            print("Starting Pyphisher...")
            run_command("python3 Pyphisher/pyphisher.py")
        elif choice == '2':
            print("You have selected AdvPhishing.")
            run_command("git clone https://github.com/AdvPhishing/AdvPhishing.git")
            print("AdvPhishing has been cloned successfully.")
            run_command("cd AdvPhishing && chmod +x advphishing.sh")
            print("Starting AdvPhishing...")
            run_command("bash AdvPhishing/advphishing.sh")
        elif choice == '3':
            print("You have selected HiddenEye.")
            run_command("git clone https://github.com/DarkSecDevelopers/HiddenEye.git")
            print("HiddenEye has been cloned successfully.")
            run_command("cd HiddenEye && chmod +x HiddenEye.py")
            print("Starting HiddenEye...")
            run_command("python3 HiddenEye/HiddenEye.py")
        elif choice == '4':
            print("You have selected zphisher.")
            run_command("git clone https://github.com/htr-tech/zphisher.git")
            print("zphisher has been cloned successfully.")
            run_command("cd zphisher && chmod +x zphisher.sh")
            print("Starting zphisher...")
            run_command("bash zphisher/zphisher.sh")
        elif choice == '5':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_7():
    while True:
        print("\nWeb Attack Tool Options:")
        print("[1] Web2Attack")
        print("[2] Skipfish")
        print("[3] CheckURL")
        print("[4] Blazy")
        print("[5] Dirb")
        print("[6] Back to Main Menu")
        
        choice = input("Select an option (1-6): ")
        
        if choice == '1':
            print("You have selected Web2Attack.")
            run_command("git clone https://github.com/evait-security/web2attack.git")
            print("Web2Attack has been cloned successfully.")
            run_command("cd web2attack && chmod +x web2attack.py")
            print("Starting Web2Attack...")
            run_command("python3 web2attack/web2attack.py")
        elif choice == '2':
            print("You have selected Skipfish.")
            run_command("sudo apt install skipfish -y")
            print("Skipfish has been installed successfully.")
            print("Starting Skipfish...")
            target_url = input("Please enter the target URL: ")
            run_command(f"skipfish -o output_dir {target_url}")
        elif choice == '3':
            print("You have selected CheckURL.")
            run_command("git clone https://github.com/CheckURL/CheckURL.git")
            print("CheckURL has been cloned successfully.")
            run_command("cd CheckURL && chmod +x checkurl.py")
            print("Starting CheckURL...")
            run_command("python3 CheckURL/checkurl.py")
        elif choice == '4':
            print("You have selected Blazy.")
            run_command("git clone https://github.com/Blazy/Blazy.git")
            print("Blazy has been cloned successfully.")
            run_command("cd Blazy && chmod +x blazy.py")
            print("Starting Blazy...")
            run_command("python3 Blazy/blazy.py")
        elif choice == '5':
            print("You have selected Dirb.")
            run_command("sudo apt install dirb -y")
            print("Dirb has been installed successfully.")
            print("Starting Dirb...")
            target_url = input("Please enter the target URL: ")
            run_command(f"dirb {target_url}")
        elif choice == '6':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_8():
    while True:
        print("\nPost Exploitation Options:")
        print("[1] Vegile - Ghost In The Shell")
        print("[2] Coming Soon..")
        print("[3] Back to Main Menu")
        
        choice = input("Select an option (1-3): ")
        
        if choice == '1':
            print("You have selected Vegile - Ghost In The Shell.")
            run_command("git clone https://github.com/Veil-Framework/Vegile.git")
            print("Vegile has been cloned successfully.")
            run_command("cd Vegile && chmod +x vegile.py")
            print("Starting Vegile...")
            run_command("python3 Vegile/vegile.py")
        elif choice == '2':
            print("Coming Soon...")
            # İlgili işlemleri burada gerçekleştirin
        elif choice == '3':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_9():
    while True:
        print("\nForensic Tools Options:")
        print("[1] Autopsy")
        print("[2] Wireshark")
        print("[3] Toolsley")
        print("[4] Bulk Extractor")
        print("[5] Back to Main Menu")
        
        choice = input("Select an option (1-5): ")
        
        if choice == '1':
            print("You have selected Autopsy.")
            run_command("sudo apt install autopsy -y")
            print("Autopsy has been installed successfully.")
            print("Starting Autopsy...")
            run_command("autopsy")  # Autopsy'yi başlat
        elif choice == '2':
            print("You have selected Wireshark.")
            run_command("sudo apt install wireshark -y")
            print("Wireshark has been installed successfully.")
            print("Starting Wireshark...")
            run_command("wireshark")  # Wireshark'ı başlat
        elif choice == '3':
            print("You have selected Toolsley.")
            run_command("git clone https://github.com/Toolsley/Toolsley.git")
            print("Toolsley has been cloned successfully.")
            run_command("cd Toolsley && chmod +x toolsley.py")
            print("Starting Toolsley...")
            run_command("python3 Toolsley/toolsley.py")
        elif choice == '4':
            print("You have selected Bulk Extractor.")
            run_command("sudo apt install bulk-extractor -y")
            print("Bulk Extractor has been installed successfully.")
            print("Starting Bulk Extractor...")
            target_file = input("Please enter the target file path: ")
            run_command(f"bulk_extractor {target_file}")  # Bulk Extractor'ı başlat
        elif choice == '5':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_10():
    while True:
        print("\nPayload Creator Options:")
        print("[1] The FatRat")
        print("[2] Brutal")
        print("[3] Stitch")
        print("[4] MSFvenom Payload Creator")
        print("[5] Mob-Droid")
        print("[6] Back to Main Menu")
        
        choice = input("Select an option (1-6): ")
        
        if choice == '1':
            print("You have selected The FatRat.")
            run_command("git clone https://github.com/Screetsec/TheFatRat.git")
            print("The FatRat has been cloned successfully.")
            run_command("cd TheFatRat && chmod +x setup.sh")
            print("Starting The FatRat...")
            run_command("bash setup.sh")  # The FatRat'ı başlat
        elif choice == '2':
            print("You have selected Brutal.")
            run_command("git clone https://github.com/Brutal/Brutal.git")
            print("Brutal has been cloned successfully.")
            run_command("cd Brutal && chmod +x brutal.py")
            print("Starting Brutal...")
            run_command("python3 Brutal/brutal.py")
        elif choice == '3':
            print("You have selected Stitch.")
            run_command("git clone https://github.com/Stitch/Stitch.git")
            print("Stitch has been cloned successfully.")
            run_command("cd Stitch && chmod +x stitch.py")
            print("Starting Stitch...")
            run_command("python3 Stitch/stitch.py")
        elif choice == '4':
            print("You have selected MSFvenom Payload Creator.")
            payload_type = input("Please enter the payload type (e.g., android/meterpreter/reverse_tcp): ")
            lhost = input("Please enter your local host IP: ")
            lport = input("Please enter your local port: ")
            run_command(f"msfvenom -p {payload_type} LHOST={lhost} LPORT={lport} -f exe > payload.exe")
            print("Payload created successfully as payload.exe.")
        elif choice == '5':
            print("You have selected Mob-Droid.")
            run_command("git clone https://github.com/Mob-Droid/Mob-Droid.git")
            print("Mob-Droid has been cloned successfully.")
            run_command("cd Mob-Droid && chmod +x setup.sh")
            print("Starting Mob-Droid...")
            run_command("bash setup.sh")  # Mob-Droid'ı başlat
        elif choice == '6':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_11():
    while True:
        print("\nRouter Exploit Options:")
        print("[1] Fluxion")
        print("[2] Wifiphisher")
        print("[3] Howmanypeople")
        print("[4] Back to Main Menu")
        
        choice = input("Select an option (1-4): ")
        
        if choice == '1':
            print("You have selected Fluxion.")
            run_command("git clone https://github.com/FluxionNetwork/fluxion.git")
            print("Fluxion has been cloned successfully.")
            run_command("cd fluxion && chmod +x fluxion.sh")
            print("Starting Fluxion...")
            run_command("sudo ./fluxion.sh")  # Fluxion'ı başlat
        elif choice == '2':
            print("You have selected Wifiphisher.")
            run_command("git clone https://github.com/wifiphisher/wifiphisher.git")
            print("Wifiphisher has been cloned successfully.")
            run_command("cd wifiphisher && sudo python3 setup.py install")
            print("Starting Wifiphisher...")
            run_command("sudo wifiphisher")  # Wifiphisher'ı başlat
        elif choice == '3':
            print("You have selected Howmanypeople.")
            run_command("git clone https://github.com/HowManyPeople/howmanypeople.git")
            print("Howmanypeople has been cloned successfully.")
            run_command("cd howmanypeople && chmod +x howmanypeople.sh")
            print("Starting Howmanypeople...")
            run_command("sudo ./howmanypeople.sh")  # Howmanypeople'ı başlat
        elif choice == '4':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_12():
    while True:
        print("\nWifi Jamming Options:")
        print("[1] WifiJammer-NG")
        print("[2] KawaiiDeauther")
        print("[3] Back to Main Menu")
        
        choice = input("Select an option (1-3): ")
        
        if choice == '1':
            print("You have selected WifiJammer-NG.")
            run_command("git clone https://github.com/wiire/WifiJammer-NG.git")
            print("WifiJammer-NG has been cloned successfully.")
            run_command("cd WifiJammer-NG && chmod +x wifi-jammer-ng.py")
            print("Starting WifiJammer-NG...")
            run_command("python3 WifiJammer-NG/wifi-jammer-ng.py")
        elif choice == '2':
            print("You have selected KawaiiDeauther.")
            run_command("git clone https://github.com/spacehuhn/KawaiiDeauther.git")
            print("KawaiiDeauther has been cloned successfully.")
            run_command("cd KawaiiDeauther && chmod +x KawaiiDeauther.py")
            print("Starting KawaiiDeauther...")
            run_command("python3 KawaiiDeauther/KawaiiDeauther.py")
        elif choice == '3':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_13():
    while True:
        print("\nSocial Media Attack Options:")
        print("[1] instaBrute")
        print("[2] AllinOne SocialMedia Attack")
        print("[3] Facebook BruteForcer")
        print("[4] Application Checker")
        print("[5] Back to Main Menu")
        
        choice = input("Select an option (1-5): ")
        
        if choice == '1':
            print("You have selected instaBrute.")
            run_command("git clone https://github.com/instaBrute/instaBrute.git")
            print("instaBrute has been cloned successfully.")
            run_command("cd instaBrute && chmod +x instaBrute.py")
            print("Starting instaBrute...")
            run_command("python3 instaBrute.py")  # instaBrute'ı başlat
        elif choice == '2':
            print("You have selected AllinOne SocialMedia Attack.")
            run_command("git clone https://github.com/AllinOneSocialMediaAttack/allinone.git")
            print("AllinOne SocialMedia Attack has been cloned successfully.")
            run_command("cd allinone && chmod +x allinone.py")
            print("Starting AllinOne SocialMedia Attack...")
            run_command("python3 allinone.py")  # AllinOne SocialMedia Attack'ı başlat
        elif choice == '3':
            print("You have selected Facebook BruteForcer.")
            run_command("git clone https://github.com/facebookBruteForcer/facebookBruteForcer.git")
            print("Facebook BruteForcer has been cloned successfully.")
            run_command("cd facebookBruteForcer && chmod +x fbBrute.py")
            print("Starting Facebook BruteForcer...")
            run_command("python3 fbBrute.py")  # Facebook BruteForcer'ı başlat
        elif choice == '4':
            print("You have selected Application Checker.")
            run_command("git clone https://github.com/ApplicationChecker/appchecker.git")
            print("Application Checker has been cloned successfully.")
            run_command("cd appchecker && chmod +x appchecker.py")
            print("Starting Application Checker...")
            run_command("python3 appchecker.py")  # Application Checker'ı başlat
        elif choice == '5':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_14():
    while True:
        print("\nSocial Media Finder Options:")
        print("[1] FindUser ")
        print("[2] Sherlock")
        print("[3] SocialScan")
        print("[4] Back to Main Menu")
        
        choice = input("Select an option (1-4): ")
        
        if choice == '1':
            print("You have selected FindUser .")
            run_command("git clone https://github.com/FindUser /finduser.git")
            print("FindUser  has been cloned successfully.")
            run_command("cd finduser && chmod +x finduser.py")
            print("Starting FindUser ...")
            run_command("python3 finduser.py")  # FindUser 'ı başlat
        elif choice == '2':
            print("You have selected Sherlock.")
            run_command("git clone https://github.com/sherlock-project/sherlock.git")
            print("Sherlock has been cloned successfully.")
            run_command("cd sherlock && chmod +x sherlock.py")
            print("Starting Sherlock...")
            run_command("python3 sherlock/sherlock.py")  # Sherlock'ı başlat
        elif choice == '3':
            print("You have selected SocialScan.")
            run_command("git clone https://github.com/abduallah/socialscan.git")
            print("SocialScan has been cloned successfully.")
            run_command("cd socialscan && chmod +x socialscan.py")
            print("Starting SocialScan...")
            run_command("python3 socialscan/socialscan.py")  # SocialScan'ı başlat
        elif choice == '4':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_15():
    while True:
        print("\nAndroid Hack Options:")
        print("[1] Keydroid")
        print("[2] MySMS")
        print("[3] DroidCam")
        print("[4] Lockphish")
        print("[5] Back to Main Menu")
        
        choice = input("Select an option (1-5): ")
        
        if choice == '1':
            print("You have selected Keydroid.")
            run_command("git clone https://github.com/Keydroid/keydroid.git")
            print("Keydroid has been cloned successfully.")
            run_command("cd keydroid && chmod +x keydroid.py")
            print("Starting Keydroid...")
            run_command("python3 keydroid.py")  # Keydroid'ı başlat
        elif choice == '2':
            print("You have selected MySMS.")
            run_command("git clone https://github.com/MySMS/mysms.git")
            print("MySMS has been cloned successfully.")
            run_command("cd mysms && chmod +x mysms.py")
            print("Starting MySMS...")
            run_command("python3 mysms/mysms.py")  # MySMS'i başlat
        elif choice == '3':
            print("You have selected DroidCam.")
            run_command("git clone https://github.com/DroidCam/droidcam.git")
            print("DroidCam has been cloned successfully.")
            run_command("cd droidcam && chmod +x droidcam.py")
            print("Starting DroidCam...")
            run_command("python3 droidcam/droidcam.py")  # DroidCam'ı başlat
        elif choice == '4':
            print("You have selected Lockphish.")
            run_command("git clone https://github.com/Lockphish/lockphish.git")
            print("Lockphish has been cloned successfully.")
            run_command("cd lockphish && chmod +x lockphish.py")
            print("Starting Lockphish...")
            run_command("python3 lockphish/lockphish.py")  # Lockphish'i başlat
        elif choice == '5':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_16():
    while True:
        print("\nPort Forwarding Options:")
        print("[1] Coming Soon...")
        print("[2] Back to Main Menu")
        
        choice = input("Select an option (1-2): ")
        
        if choice == '1':
            print("Coming Soon...")
            # İlgili işlemleri burada gerçekleştirin
        elif choice == '2':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_17():
    while True:
        print("\nOther Tools Options:")
        print("[1] HatCloud - A tool for cloud-based attacks and information gathering.")
        print("[2] Asyncrone - A tool for asynchronous network scanning and exploitation.")
        print("[3] GoldenEye - A DoS attack tool that can be used to test the resilience of web servers.")
        print("[4] SaphyraDDoS - A DDoS attack tool designed for testing the robustness of networks.")
        print("[5] Knockmail - A tool for email enumeration and verification.")
        print("[6] Back to Main Menu")
        
        choice = input("Select an option (1-6): ")
        
        if choice == '1':
            print("You have selected HatCloud.")
            run_command("git clone https://github.com/hatcloud/hatcloud.git")
            print("HatCloud has been cloned successfully.")
            run_command("cd hatcloud && chmod +x hatcloud.py")
            print("Starting HatCloud...")
            run_command("python3 hatcloud.py")  # HatCloud'ı başlat
        elif choice == '2':
            print("You have selected Asyncrone.")
            run_command("git clone https://github.com/Asyncrone/asyncrone.git")
            print("Asyncrone has been cloned successfully.")
            run_command("cd asyncrone && chmod +x asyncrone.py")
            print("Starting Asyncrone...")
            run_command("python3 asyncrone.py")  # Asyncrone'ı başlat
        elif choice == '3':
            print("You have selected GoldenEye.")
            run_command("git clone https://github.com/jseidl/GoldenEye.git")
            print("GoldenEye has been cloned successfully.")
            run_command("cd GoldenEye && chmod +x goldeneye.py")
            print("Starting GoldenEye...")
            run_command("python3 goldeneye.py")  # GoldenEye'ı başlat
        elif choice == '4':
            print("You have selected SaphyraDDoS.")
            run_command("git clone https://github.com/SaphyraDDoS/SaphyraDDoS.git")
            print("SaphyraDDoS has been cloned successfully.")
            run_command("cd SaphyraDDoS && chmod +x saphyra.py")
            print("Starting SaphyraDDoS...")
            run_command("python3 saphyra.py")  # SaphyraDDoS'ı başlat
        elif choice == '5':
            print("You have selected Knockmail.")
            run_command("git clone https://github.com/evait-security/KnockMail.git")
            print("Knockmail has been cloned successfully.")
            run_command("cd KnockMail && chmod +x knockmail.py")
            print("Starting Knockmail...")
            run_command("python3 knockmail.py")  # Knockmail'ı başlat
        elif choice == '6':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def option_5():
    while True:
        print("\nPassword Attacks Options:")
        print("[1] Hash Buster - A tool designed to help identify and crack password hashes.")
        print("[2] Hashcat - A powerful password recovery tool that supports a wide range of hashing algorithms.")
        print("[3] Cupp - Common User Passwords Profiler that generates password lists based on user information.")
        print("[4] WordlistCreator - A utility for creating custom wordlists for password cracking.")
        print("[5] Goblin WordGenerator - A tool that generates password lists using various algorithms and rules.")
        print("[6] Password List (1.4 Billion Clear Text Password) - A comprehensive collection of passwords available at https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got")
        print("[7] Back to Main Menu")
        
        choice = input("Select an option (1-7): ")
        
        if choice == '1':
            print("You have selected Hash Buster.")
            run_command("git clone https://github.com/yourusername/hashbuster.git")  # Replace with actual URL
            print("Hash Buster has been cloned successfully.")
            run_command("cd hashbuster && chmod +x hashbuster.py")
            print("Starting Hash Buster...")
            run_command("python3 hashbuster.py")  # Hash Buster'ı başlat
        elif choice == '2':
            print("You have selected Hashcat.")
            run_command("git clone https://github.com/hashcat/hashcat.git")
            print("Hashcat has been cloned successfully.")
            run_command("cd hashcat && make")
            print("Starting Hashcat...")
            run_command("hashcat --help")  # Hashcat yardımını göster
        elif choice == '3':
            print("You have selected Cupp.")
            run_command("git clone https://github.com/Mebus/cupp.git")
            print("Cupp has been cloned successfully.")
            run_command("cd cupp && chmod +x cupp.py")
            print("Starting Cupp...")
            run_command("python3 cupp.py")  # Cupp'ı başlat
        elif choice == '4':
            print("You have selected WordlistCreator.")
            run_command("git clone https://github.com/yourusername/wordlistcreator.git")  # Replace with actual URL
            print("WordlistCreator has been cloned successfully.")
            run_command("cd wordlistcreator && chmod +x wordlistcreator.py")
            print("Starting WordlistCreator...")
            run_command("python3 wordlistcreator.py")  # WordlistCreator'ı başlat
        elif choice == '5':
            print("You have selected Goblin WordGenerator.")
            run_command("git clone https://github.com/yourusername/goblinwordgenerator.git")  # Replace with actual URL
            print("Goblin WordGenerator has been cloned successfully.")
            run_command("cd goblinwordgenerator && chmod +x goblinwordgenerator.py")
            print("Starting Goblin WordGenerator...")
            run_command("python3 goblinwordgenerator.py")  # Goblin WordGenerator'ı başlat
        elif choice == '6':
            print("You have selected Password List (1.4 Billion Clear Text Password).")
            print("You can download the password list from: https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got")
        elif choice == '7':
            print("Going back to the main menu.")
            break  # Ana menüye dön
        else:
            print("Invalid option. Please try again.")

def main():
    show_main_menu()  # Ana menüyü göster

    while True:
        choice = input("Select an option (1-18): ")

        if choice == '1':
            option_1()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '2':
            option_2()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '3':
            option_3()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '4':
            option_4()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '5':
            option_5()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '6':
            option_6()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '7':
            option_7()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '8':
            option_8()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '9':
            option_9()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '10':
            option_10()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '11':
            option_11()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '12':
            option_12()  # Wifi Jamming seçeneği
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '13':
            option_13()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '14':
            option_14()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '15':
            option_15()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '16':
            option_16()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '17':
            option_17()
            show_main_menu()  # Ana menüyü tekrar göster
        elif choice == '18':
            print("Exiting the tool.")
            break
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()