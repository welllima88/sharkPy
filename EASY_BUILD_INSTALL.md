## Easiest Way to get/install
1. Create 64-bit CentOS 7 VM. In VM run following as root:<br>
    a. yum install libpcap-devel<br>
    b. yum install glib2-devel<br>
    c. yum install libnl-devel<br>
    d. yum install libgcrypt-devel<br>
2. In VM web browser...Go here: https://drive.google.com/file/d/0B64GIIlkLQC6TzlTaVB6d1hNZ0E/view?usp=sharing. Get sharkPyBundled.tgz. Blithely ignore Google's 'can't scan for viruses' warning. File is too big. Besides, you can trust me! :)<br>
3. cd into directory containing downloaded tarball. and run 'tar -zxvf sharkPyBundled.tgz'.<br>
4. cd sp<br>
5. sudo ./setup.py install --or-- sudo python setup.py install<br>
6. profit!<br>

#Note
Other 64-bit linux distros should work as well. However, you'll still need to install the above libs (in step 1) or equivalent.
