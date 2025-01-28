# **Anket**

## **Introduction**
Anket is an open-source tool designed to **identify botnet Command and Control (C2) servers**. This project is purely for educational purposes, aimed at helping understand and analyze the malicious infrastructures of botnets. **Anket is not intended for malicious or illegal use.**

I am not a professional developer, but I am passionate about cybersecurity and curious to explore botnet mechanisms. Anket represents my efforts to learn, share knowledge, and contribute to online safety.

---

## **Main Features**
- **ASN and IP Analysis**: Queries IP ranges associated with specific ASNs using the WHOIS protocol.
- **Suspicious Network Activity Detection**: Scans IP ranges to identify potentially malicious servers.
- **Banner Analysis**: Compares open service banners with known patterns to detect:
  - Signatures of specific malware.
  - Potentially legitimate services.
- **Telegram Notifications**: Sends real-time alerts when malicious servers are detected.
- **Advanced Logging**: Provides detailed, color-coded logs to monitor scanning progress.

---

## **Prerequisites**
Before using Anket, ensure the following dependencies are installed:

### **Required Software**
- **Python 3.8+**
- **fping**: For connectivity testing on IP ranges.
- **rustscan**: For fast and efficient port scanning.

### **Python Modules**
- `asyncio`
- `re`
- `socket`
- `subprocess`
- `shutil`
- `logging`
- **Additional dependencies** (installed via `pip install -r requirements.txt`):
  - `colorama`
  - `pyTelegramBotAPI`

---

## **Installation**
1. Clone the project from GitHub:
   ```bash
   > git clone https://github.com/redrabytes/anket.git
   > cd anket
   ```

2. Install the required dependencies:
   ```bash
   > pip install .
   ```

3. You can now run Anket using the command:
   ```bash
   > anket
   ```
3. Ensure `fping` and `rustscan` are installed and available in your `PATH`.

4. Set up your Telegram bot by following these steps:
   - Create a bot via [@BotFather](https://t.me/BotFather) and get your token.
   - Add the token to the project configuration file.

5. Building the binary

---

## **Usage**
### **Main Commands**
- **Start a scan:**
   ```bash
  > anket --help

         ,;;;,
        ;;;;;;;
     .-'`\, '/_    _______       ______      _____ 
   .'   \ ("\`(_)   ___    |_________  /________  /_
  / `-,.'\ \_/     __  /| |_  __ \_  //_/  _ \  __/
  \  \/\  `--`    _  ___ |  / / /  ,<  /  __/ /_ 
   \  \ \         /_/  |_/_/ /_//_/|_| \___/\__/
    / /| |
   /_/ |_|
  ( _\ ( _\  #:##        #:##        #:##         #:##
                   #:##        #:##        #:##
  
  usage: anket TARGET [-h] [-s] [-asn] [-co] [-sv OUTPUT_FILE] [-tele]
  
  Anket: a tool to find Indicators of Compromise (IOC) and track malware activity.
  
  positional arguments:
    TARGET           IP address, CIDR, ASN, or filename containing targets.
  
  optional arguments:
    -h, --help       Show this help message and exit.
    -s               Start a port-scanner & sensor to detect C&C server.
    -asn             Print IP list from the AS given.
    -co              Check online IP (ICMP).
    -tele            Send report through Telegram.
    -sv OUTPUT_FILE  Save results in file.
  
  examples:
    anket.txt <options>
    anket 192.168.0.1 <options>
    anket AS197637 <options>
   ```

- **Telegram Notification:**
   Configure the Telegram bot to receive alerts for detected open-dir servers.

---

## **Disclaimer**
Anket is designed **for educational and defensive purposes only**. I am not responsible for any misuse or illegal activities conducted using this tool. Always ensure compliance with the laws in your country regarding network analysis and cybersecurity.

---

## **Contributions**
If you’d like to contribute to improving this project, suggestions, bug reports, and pull requests are welcome! Since I’m not a professional developer, any help to make the code more robust and efficient is greatly appreciated.

---

## **Contact**
If you have questions or suggestions, feel free to reach out to me via GitHub or Twitter.

---
