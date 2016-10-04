
#VM INSTALL

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

#DOCKER

##Set up
First, make sharkPy directory and place Dockerfile into it. cd into this new directory.<br/>

##Build sharkPy Docker image
docker build -t "ubuntu16_04:sharkPy" .   #Build will take a while and should be completely automated.<br/>
Notes: </br>
* sharkPy dist code will be in /sharkPy<br/>
* build creates Ubuntu 16.04 image and installs sharkPy as a Python module<br/>

##Run interactively as Docker container. 
###Should give you command prompt
docker run -it ubuntu16_04:sharkPy /bin/bash<br/>

###Command prompt and access to host NICs (to allow for network capture)
docker run -it --net=host ubuntu16_04:sharkPy /bin/bash<br/>

###Command prompt and mount directory (to access PCAPs)
TO-DO<br/>

