from anket.core import * 
from anket.modules.robot.main import *

known_ports = {
    20: ('FTP', r'220[\s\-]FTP|FileZilla|vsFTPd|Pure\-FTPd|ProFTPD', b'USER anonymous\r\n'),
    21: ('FTP', r'220[\s\-]FTP|FileZilla|vsFTPd|Pure\-FTPd|ProFTPD', b'USER anonymous\r\n'),
    22: ('SSH', r'SSH\-2\.0\-OpenSSH|SSH\-2\.0\-Dropbear|SSH\-2\.0\-libssh|SSH\-2\.0\-FortiOS', None),
    23: ('Telnet', r'Telnet|Escape sequence', b'help\r\n'),
    25: ('SMTP', r'220\sSMTP|Postfix|Exim|Sendmail|qmail', None),
    53: ('DNS', r'BIND|PowerDNS|Unbound', None),
    80: ('HTTP', r'HTTP/[\d.]+|Apache|nginx|LiteSpeed|Microsoft\-IIS|Caddy|Tengine|OpenResty|cloudflare', b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'),
    110: ('POP3', r'POP3 server ready|Dovecot|Courier', None),
    115: ('SFTP', r'SFTP|SSH\-2\.0', None),
    123: ('NTP', r'NTP server|ntpd|chrony', None),
    143: ('IMAP', r'IMAP server ready|Dovecot|Courier', None),
    161: ('SNMP', r'SNMP|Net\-SNMP', None),
    194: ('IRC', r'Internet Relay Chat|UnrealIRCd|InspIRCd', None),
    443: ('HTTPS', r'HTTP/[\d.]+|Apache|nginx|LiteSpeed|Microsoft\-IIS|OpenResty|Tengine|cloudflare', b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'),
    445: ('SMB', r'SMB|Samba|Microsoft\-DS', None),
    465: ('SMTPS', r'SMTPS|Postfix|Exim|Sendmail', None),
    554: ('RTSP', r'RTSP/[\d.]+|VLC|LIVE555', None),
    873: ('RSYNC', r'rsync daemon', None),
    993: ('IMAPS', r'IMAPS server ready|Dovecot|Courier', None),
    995: ('POP3S', r'POP3S server ready|Dovecot|Courier', None),
    3389: ('RDP', r'RDP|Remote Desktop|TLS handshake', None),
    5631: ('PC Anywhere', r'PCAnywhere', None),
    3306: ('MySQL', r'MySQL server|MariaDB|Percona|mysql_native_password', None),
    5432: ('PostgreSQL', r'PostgreSQL server', None),
    5900: ('VNC', r'RFB \d+\.\d+|VNC', None),
    8021: ('FTP Proxy', r'FreeSWITCH|8021', None)
}

malicious_pattern = {
    'Moobot': r'3f',
    'Escape sequence': r'[\x1b\x01\x03]',
    'Mirai': r'Username',
    'Pan-Chan': r'pan-chan',
    'Golang SSH': r'SSH-2.0-Go'
}

def is_open_directory(response_text):
    return "Index of" in response_text or re.search(r'Index of', response_text, re.IGNORECASE)

def title(response_text):
    match = re.search(r'<title>(.*?)</title>', response_text, re.IGNORECASE)
    return match.group(1) if match else None

def href(response_text, ip):
    links = set()
    soup = BeautifulSoup(response_text, 'html.parser')
    for link in soup.find_all("a")[5:]:
        if link.attrs["href"].endswith('/'):
            continue
        links.add(f"{ip}/{link.attrs['href']}")
            
    return links
    
def s(ip, port, timeout, command):
    s = socket.socket()
    s.settimeout(timeout)
    
    try:
        s.connect((ip, port))
        s.send(command)
        banner = s.recv(65535).decode('utf-8', errors='ignore')
        return repr(banner) if banner else None
    except (TimeoutError, Exception):
        return None
    finally:
        s.close()

async def service_status(ip, port, bot):
    service_name, service_regex, command = None, None, None

    if port in known_ports:
        service_name, service_regex, command = known_ports[port]

    if not command:
        command = b"Hey!\n"
        
    if b"example.com" in command: 
        command = command.replace(b'example.com', ip.encode('utf-8'))

        
    response = s(ip, port, 5, command)
    
    if response is None:
        return port, "unknown", "offline"

    if service_regex and re.search(service_regex, response):        
        if is_open_directory(response):
            HREF = href(response, ip)
            print(HREF)
            if bot and HREF:
                await TelegramMessage(chat_id=os.getenv("CHAT_ID"), message="{}: {}".format(ip, HREF), bot=bot)
            return port, f"{service_name} - open-dir", "legit"
        return port, service_name, "legit"
            
    for mal_name, mal_regex in malicious_pattern.items():
        if re.search(mal_regex, response):
            return port, mal_name, "malware"
            
    for known_port, (name, regex, _) in known_ports.items():
        if is_open_directory(response):
            HREF = href(response, ip)
            if bot and HREF:
                await TelegramMessage(chat_id=os.getenv("CHAT_ID"), message="{}: {}".format(ip, HREF), bot=bot)
            return port, f"{name} - open-dir", "legit"
        elif re.search(regex, response):
            return port, name, "legit"
            
    return port, "unknown", "potential c2"