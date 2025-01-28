import re
import os
import sys
import csv
import time
import whois
import shutil
import socket
import select
import asyncio
import logging
import debugpy
import argparse
import subprocess

from telebot.async_telebot import AsyncTeleBot
from dotenv import load_dotenv, find_dotenv
from colorama import Fore, Style, init
from bs4 import BeautifulSoup

from anket.modules.logger.main import *
from anket.modules.gather.main import *
from anket.modules.sensor.main import *
from anket.modules.robot.main import *

load_dotenv(find_dotenv())

CIDR_REGEX = re.compile(r'((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[1-9]?[0-9])\/([0-9]|[1-2][0-9]|3[0-2])')
IP_REGEX = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
ASN_REGEX = re.compile(r'^AS([1-9]\d{0,9})$')
DOMAIN_REGEX = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

scanned_ip = set()

def is_cidr(data):
    return CIDR_REGEX.match(data)

def is_ipaddress(data):
    return IP_REGEX.match(data)

def is_asn(data):
    return ASN_REGEX.match(data)

def is_domain(data):
    return DOMAIN_REGEX.match(data)

def sort_list():
    alive.clear()
    for ip, ip_type in ip_list:
        alive.update(get_alive(ip, ip_type))
    return alive

def handle_target(target):
    try:
        if os.path.isfile(target):
            logger.info(f"Loading targets from {target}")
            with open(target, "r") as file:
                for line in file:
                    line = line.strip()
                    if is_ipaddress(line):
                        ip_list.add((line, "ip"))
                    elif is_cidr(line):
                        ip_list.add((line, "cidr"))
                    elif is_asn(line):
                        logger.info(f"Extracting ASN addresses {line}")
                        for addresses in get_asn(line):
                            ip_list.add((addresses, "cidr"))
                    elif is_domain(line):
                        logger.info(f"Resolving {line}")
                        try:
                            resolve = socket.gethostbyname(target)
                            ip_list.add((resolve, "ip"))
                        except socket.gaierror:
                            pass                                                   
            logger.info(f"Total targets found: {len(ip_list)}")
        elif is_asn(target):
            logger.info(f"Fetching addresses from {target}")
            for addresses in get_asn(target):
                ip_list.add((addresses, "cidr"))
        elif is_ipaddress(target):
            ip_list.add((target, "ip"))
        elif is_cidr(target):
            ip_list.add((target, "cidr"))
        elif is_domain(target):
            logger.info(f"Resolving {target}")
            try:
                resolve = socket.gethostbyname(target)
                ip_list.add((resolve, "ip"))
            except socket.gaierror:
                pass             
        else:
            logger.error("No data found matching regexs.")
            raise ValueError("No data found matching regexs.")
    except FileNotFoundError:
        logger.error(f"File not found: {target}")
        raise ValueError(f"File not found: {target}")
    except Exception as e:
        logger.error(f"Error handling target {target}: {e}")
        raise ValueError(f"Error handling target {target}: {e}")

def export_data_to_csv(filename, parsed_data):
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["IP", "PORT", "MALICIOUS PORT", "POTENTIAL MALICIOUS PORT"])
            for entry in parsed_data:
                if not all(k in entry for k in ["IP", "PORT", "MALICIOUS", "POTENTIAL"]):
                    logger.warning(f"Skipping malformed entry: {entry}")
                    continue
                csv_writer.writerow([
                    entry["IP"],
                    entry["PORT"],
                    entry["MALICIOUS"],
                    entry["POTENTIAL"]
                ])
        logger.info(f"Data successfully exported to {filename}")
    except IOError as e:
        logger.error(f"Failed to write to file {filename}: {e}")
        print(f"Failed to export data to CSV: {e}")
  
def main():
    print(f"""{Fore.LIGHTWHITE_EX}
       ,;;;,
      ;;;;;;;
   .-'`\\, '/_    {Fore.LIGHTBLUE_EX}_______       ______      _____ {Style.RESET_ALL}
 .'   \\ ("`(_)   {Fore.LIGHTBLUE_EX}___    |_________  /________  /_{Style.RESET_ALL}
/ `-,.'\\ \\_/    {Fore.LIGHTBLUE_EX} __  /| |_  __ \\_  //_/  _ \\  __/{Style.RESET_ALL}
\\  \\/\\  `--`   {Fore.LIGHTBLUE_EX} _  ___ |  / / /  ,<  /  __/ /_ {Style.RESET_ALL}
 \\  \\ \\        {Fore.LIGHTBLUE_EX} /_/  |_/_/ /_//_/|_| \\___/\\__/{Style.RESET_ALL}
  / /| |
 /_/ |_|
( _\\ ( _\\  {Fore.LIGHTRED_EX}#:##        #:##        #:##         #:##
                 #:##        #:##        #:##
{Style.RESET_ALL}""")

    parser = argparse.ArgumentParser(
        prog="Anket",
        description="Anket: a tool to find Indicators of Compromise (IOC) and track malware activity.",
        usage="anket TARGET [-h] [-s] [-asn] [-co] [-sv OUTPUT_FILE] [-tele]",
        epilog="examples:\n  anket.txt <options>\n  anket 192.168.0.1 <options>\n  anket AS197637 <options>",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )

    parser.add_argument('TARGET', help="IP address, CIDR, ASN, or filename containing targets.")
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit.')
    parser.add_argument('-s', help="Start a port-scanner & sensor to detect C&C server.", action="store_true")
    parser.add_argument('-asn', help="Print IP list from the AS given.", action="store_true")
    parser.add_argument('-co', help="Check online IP (ICMP).", action="store_true")
    parser.add_argument('-tele', help="Send report through Telegram.", metavar="store_true")
    parser.add_argument('-sv', help="Save results in file.", metavar="OUTPUT_FILE")
    args = parser.parse_args()

    if len(sys.argv) <= 2: return parser.print_help()

    target = args.TARGET
    handle_target(target)

    alive_ips = set()
    
    bot = None
    
    if args.tele:
        TELEBOT_TOKEN = os.getenv("TELEGRAM_TOKEN")
        CHAT_ID = os.getenv("CHAT_ID")
        
        if not TELEBOT_TOKEN:
            logger.error("No token found for Telegram")
            raise ValueError("Add your token in `.env` in `TELEBOT` variable to use -tele parameter")
        elif not os.getenv("CHAT_ID"):
            logger.error("No chat ID was found to send info through Telegram")
            raise ValueError("Please add chat IDs in `.env` in `CHAT_ID` variable to use -tele parameter")
        
        bot = AsyncTeleBot(token=TELEBOT_TOKEN)
        
    if args.co:
        if ip_list:
            logger.info("Performing ICMP check to find online IP")
            alive_ips = sort_list()
            print('\r\x1B[K', end='')
        else:
            raise ValueError("No IP was found in variables")

    if args.s:
        if alive_ips:
            logger.info(f"Scanning {len(alive_ips)} alive IP...")
            data = asyncio.run(scan_all_ports(alive_ips, bot if bot else None))
        elif ip_list:
            tmp = set([(ip) for ip, _ in ip_list])
            logger.info(f"Scanning {len(ip_list)} IP...")
            data = asyncio.run(scan_all_ports(tmp, bot if bot else None))

        parsed_data = []

    if args.sv:
        for entry in data:
            if entry:
                ports = " | ".join([f"{p[0]}/{p[1]}" for p in entry[1]])
                potential_ports = " | ".join([f"{p[0]}/{p[1]}" for p in entry[3]])
                malicious_ports = " | ".join([f"{p[0]}/{p[1]}" for p in entry[2]])

                parsed_data.append({
                    "IP": entry[0],
                    "PORT": ports,
                    "MALICIOUS": malicious_ports,
                    "POTENTIAL": potential_ports
                })

        export_data_to_csv(args.sv, parsed_data)


    if args.asn:
        if alive_ips:
            print('\r')
            for ip in alive:
                print(ip)
                if args.tele:
                    asyncio.run(TelegramMessage(chat_id=CHAT_ID, message=ip, bot=bot))

if __name__ == '__main__':
    main()