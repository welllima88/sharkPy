#BUILDING

##Requried Wireshark libs. 

Required Wireshark libs can be found in Wireshark-2.0.1 stable release. Newer will probably work as well. Older will not work. Required libs must be in system lib search path. My config looks like this.

[me@localhost ~]$ ls -l /usr/local/lib<br>
total 173384<br>
lrwxrwxrwx. 1 root root        21 Jul  5 14:09 libwireshark.so -> libwireshark.so.6.0.1<br>
lrwxrwxrwx. 1 root root        21 Jul  5 14:09 libwireshark.so.6 -> libwireshark.so.6.0.1<br>
-rwxr-xr-x. 1 root root 175362146 Jul  5 14:09 libwireshark.so.6.0.1<br>
lrwxrwxrwx. 1 root root        19 Jul  5 14:09 libwiretap.so -> libwiretap.so.5.0.1<br>
lrwxrwxrwx. 1 root root        19 Jul  5 14:09 libwiretap.so.5 -> libwiretap.so.5.0.1<br>
-rwxr-xr-x. 1 root root   1760476 Jul  5 14:09 libwiretap.so.5.0.1<br>
lrwxrwxrwx. 1 root root        18 Jul  5 14:09 libwsutil.so -> libwsutil.so.6.0.0<br>
lrwxrwxrwx. 1 root root        18 Jul  5 14:09 libwsutil.so.6 -> libwsutil.so.6.0.0<br>
-rwxr-xr-x. 1 root root    413792 Jul  5 14:09 libwsutil.so.6.0.0<br>
drwxr-xr-x. 3 root root        20 Jul  1 11:37 wireshark<br>

SharkPy expects Wireshark plugins to be in site.getsitepackages/sharkPy/64_bit_libs/plugins. Looks like this on my system.<br>

[me@localhost ~]$ ls -l /usr/lib64/python2.7/site-packages/sharkPy/dissect/64_bit_libs/plugins/<br>
total 6200<br>
-rw-rw-r--. 1 root root     967 Jul  5 21:08 docsis.la<br>
-rw-rw-r--. 1 root root  823445 Jul  5 21:08 docsis.so<br>
-rw-rw-r--. 1 root root     979 Jul  5 21:08 ethercat.la<br>
-rw-rw-r--. 1 root root  317809 Jul  5 21:08 ethercat.so<br>
-rw-rw-r--. 1 root root     973 Jul  5 21:08 gryphon.la<br>
-rw-rw-r--. 1 root root  204008 Jul  5 21:08 gryphon.so<br>
-rw-rw-r--. 1 root root     955 Jul  5 21:08 irda.la<br>
-rw-rw-r--. 1 root root  156485 Jul  5 21:08 irda.so<br>
-rw-rw-r--. 1 root root     949 Jul  5 21:08 m2m.la<br>
-rw-rw-r--. 1 root root   59554 Jul  5 21:08 m2m.so<br>
-rw-rw-r--. 1 root root     955 Jul  5 21:08 mate.la<br>
-rw-rw-r--. 1 root root  305747 Jul  5 21:08 mate.so<br>
-rw-rw-r--. 1 root root     961 Jul  5 21:08 opcua.la<br>
-rw-rw-r--. 1 root root  717950 Jul  5 21:08 opcua.so<br>
-rw-rw-r--. 1 root root     979 Jul  5 21:08 profinet.la<br>
-rw-rw-r--. 1 root root 1199366 Jul  5 21:08 profinet.so<br>
-rw-rw-r--. 1 root root     991 Jul  5 21:08 stats_tree.la<br>
-rw-rw-r--. 1 root root   46019 Jul  5 21:08 stats_tree.so<br>
-rw-rw-r--. 1 root root     973 Jul  5 21:08 unistim.la<br>
-rw-rw-r--. 1 root root  285718 Jul  5 21:08 unistim.so<br>
-rw-rw-r--. 1 root root     991 Jul  5 21:08 wimaxasncp.la<br>
-rw-rw-r--. 1 root root  184343 Jul  5 21:08 wimaxasncp.so<br>
-rw-rw-r--. 1 root root     961 Jul  5 21:08 wimax.la<br>
-rw-rw-r--. 1 root root     997 Jul  5 21:08 wimaxmacphy.la<br>
-rw-rw-r--. 1 root root  196662 Jul  5 21:08 wimaxmacphy.so<br>
-rw-rw-r--. 1 root root 1766674 Jul  5 21:08 wimax.so<br>


##TO BUILD/INSTALL

In sharkPy download dir: sudo ./setup.py install.
