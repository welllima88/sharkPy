
#INSTALL

Should install/run on most linux distros as long as Wireshark version 2.0.1 or newer is installed and the following steps (or equivalent) are successful.<br/>

## ubuntu-16.04-desktop-amd64 -- clean install
sudo apt-get git<br/>
git clone https://github.com/NationalSecurityAgency/sharkPy<br/>
sudo apt-get install libpcap-dev<br/>
sudo apt-get install libglib2.0-dev<br/>
sudo apt-get install libpython-dev<br/>
sudo apt-get install wireshark-dev       #if you didn't build/install wireshark (be sure wireshark libs are in LD_LIBRARY_PATH)<br/>
sudo apt-get install wireshark           #if you didn't build/install wireshark (be sure wireshark libs are in LD_LIBRARY_PATH)<br/>
cd sharkPy<br/>
sudo ./setup install<br/>
