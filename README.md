[![EmreKybs](https://img.shields.io/badge/MadeBy-Emrekybs-blue)
# BlueFish

<img src="https://github.com/emrekybs/BlueFish/blob/main/bluefish.png">

BlueFish is a Python-based automation tool designed to simplify the analysis of PCAP (Packet Capture) files. It leverages the power of Wireshark's command-line tool, tshark, to extract valuable information from network captures. With BlueFish, you can quickly identify potential login attempts, analyze network traffic patterns, and extract various network artifacts.

## Key Features:
* Runs various Tshark commands against a folder containing pcap files (it will only grab .pcaps)
* Creates a main output folder, each unique .pcap file will have a designated folder created where results will be saved.
* Extracts potential login attempts and credentials.
* Analyzes IP and MAC addresses.
* Retrieves embedded objects from network traffic.
* Identifies email addresses and HTTP requests.
* Provides insights into protocols, DNS queries, ICMP packets, SMB operations, FTP sessions, and TLS handshakes.

BlueFish streamlines the process of PCAP analysis, making it easier for security professionals and network analysts to gain insights into network activities.

# 𝗜𝗡𝗦𝗧𝗔𝗟𝗟𝗔𝗧𝗜𝗢𝗡 𝗜𝗡𝗦𝗧𝗥𝗨𝗖𝗧𝗜𝗢𝗡𝗦
      $ git clone https://github.com/emrekybs0/BlueFish.git
      $ cd BlueFish
      $ chmod +x BlueFish.py 
      $ python3 BlueFish.py -f path/to/folder/of/pcaps -p int (4 is default)

## HELP
```
usage: BlueFish.py [-h] -f FOLDER [-p PROCESSES]

Automate pcap analysis for multiple files.

options:
  -h, --help            show this help message and exit
  -f FOLDER, --folder FOLDER
                        Folder containing .pcap files for analysis.
  -p PROCESSES, --processes PROCESSES
                        Number of parallel processes to use.
```     

<img src="3.png">
