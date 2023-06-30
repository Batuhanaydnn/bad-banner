#!/bin/bash

# Update package lists
sudo apt update

# Install required packages
sudo apt install -y git golang python3-pip

# Install Go tools
go get github.com/OJ/gobuster
go get github.com/ffuf/ffuf
go get github.com/projectdiscovery/nuclei/v2/cmd/nuclei
go get github.com/hahwul/dalfox
go get github.com/hahwul/gitGraber
go get github.com/s0md3v/xsstrike
go get github.com/hakluke/hakrawler
go get github.com/maurosoria/dirsearch
go get github.com/tomnomnom/assetfinder
go get github.com/GerbenJavado/LinkFinder
go get github.com/bhavsec/reconspider
go get github.com/haccer/subjack
go get github.com/blechschmidt/massdns
go get github.com/aboul3la/Sublist3r
go get github.com/tomnomnom/waybackurls
go get github.com/obheda12/GitDorker
go get github.com/1N3/Sn1per
go get github.com/Smaash/snitch
go get github.com/OWASP/Amass/cmd/amass
go get github.com/s0md3v/Arjun
go get github.com/maurosoria/dirhunt
go get github.com/tomnomnom/meg
go get github.com/projectdiscovery/dnsprobe
go get github.com/mandatoryprogrammer/JScanner
go get github.com/fleetcaptain/pwnback

# Install Python tools
pip3 install wpscan

# Clone and install additional tools
git clone https://github.com/OWASP/joomscan.git
cd joomscan
chmod +x joomscan.pl
sudo ln -s "$(pwd)/joomscan.pl" /usr/bin/joomscan
cd ..

# Optional: Install other tools (e.g., Nikto, Subfinder, Aquatone) using their respective installation methods

echo "Installation completed!"