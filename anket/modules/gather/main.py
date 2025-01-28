from anket.core import *
from anket.modules.sensor.main import service_status

global queue

queue = 1

ip_list = set()
alive = set()

semaphore_limit = 5

def get_asn(asn, retries=3, delay=5):
    server = 'whois.radb.net'
    port = 43

    for attempt in range(retries):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server, port))
                query = f"-i origin {asn}\r\n"
                s.send(query.encode('utf-8'))
                response = b""

                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data

            response = response.decode('utf-8')
            cidr_pattern = r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?"
            cidr = re.findall(cidr_pattern, response)
            return cidr

        except socket.gaierror as e:
            if e.errno == -3:
                logger.error(f"DNS resolution failed for {server}. Attempt {attempt + 1} of {retries}")
                time.sleep(delay)
            else:
                return logger.error(f"Socket error occurred: {e}")

    return logger.error(f"Failed to connect to WHOIS server after {retries} attempts.")

def get_alive(ip_range, ip_type):
    fping_path = shutil.which('fping')
    if fping_path is None:
        logger.critical("fping executable not found in the system PATH.")
        sys.exit(1)
    
    if ip_type not in {'cidr', 'ip'}:
        raise ValueError("Invalid type specified. Use 'cidr' or 'ip'.")
    
    command = [fping_path, '-g', ip_range] if ip_type == 'cidr' else [fping_path, ip_range]

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)        
        poller = select.poll()
        poller.register(process.stdout, select.POLLIN)
        
        while True:
            events = poller.poll(100)
            for fd, event in events:
                if event & select.POLLIN:
                    line = process.stdout.readline()
                    if 'alive' in line:
                        ip = line.split()[0]
                        alive.add(ip)
                        sys.stdout.write(f"\rTotal alive IPs found: {len(alive)}")
                        sys.stdout.flush()
            if process.poll() is not None:
                break
        
        process.stdout.close()
        process.wait()
    except Exception as e:
        raise
    finally:
        if process and process.poll() is None:
            process.kill()

    return alive

async def scan_ports(ip, semaphore, bot):
    global queue

    async with semaphore:
        proc = await asyncio.create_subprocess_shell(
            f'rustscan -a {ip} --range 1-65535 -g --',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            open_port = set()
            malware = set()
            potential_malware = set()
            
            port_message = f"[{queue}/{len(alive or ip_list)}] IP: {ip} | Open: "
            
            result = stdout.decode().strip()
            
            if "->" in result:
                queue += 1
                
                open_ports_str = result.split(' -> ')[1].strip('[]')
                open_ports = open_ports_str.split(',')

                for port_str in open_ports:
                    port = int(port_str.strip())
                    port, description, status = await service_status(ip, port, bot if bot else None)

                    if "malware" in status:
                        malware.add((port, description))
                    elif "potential c2" in status:
                        potential_malware.add((port, description))
                    elif "legit" in status:
                        open_port.add((port, description))

                    port_message += f"{port} ({description}), "
                
                if malware:
                    port_message += "| Malicious port: "
                    for port, description in malware:
                        port_message += f"{port} ({description}), "
                
                if potential_malware:
                    port_message += "| Potential malicious port: "
                    for port, description in potential_malware:
                        port_message += f"{port} ({description}), "
                        
                logger.info(port_message.rstrip(", "))
                return (ip, open_port, malware, potential_malware)
            else:
                queue += 1
                logger.info(f"[{queue}/{len(alive or ip_list)}] IP: {ip} | {Fore.RED}Offline{Style.RESET_ALL}")
        else:
            queue += 1
            logger.error(f"[{queue}/{len(alive or ip_list)}] IP: {ip} | Skipped | Reason: skipped due of error")
            
async def scan_all_ports(alive, bot):
    semaphore = asyncio.Semaphore(semaphore_limit)
    tasks = []

    for ip in alive:
        tasks.append(scan_ports(ip, semaphore, bot if bot else None))

    results = await asyncio.gather(*tasks)
    return results