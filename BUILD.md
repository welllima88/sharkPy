#BUILDING

##Requried Wireshark libs. 

Required Wireshark libs can be found in Wireshark-2.0.1 stable release. Newer will probably work as well. Older will not work. Required libs must be in system lib search path. My config looks like this.

[me@localhost ~]$ ls -l /usr/local/lib
total 173384
lrwxrwxrwx. 1 root root        21 Jul  5 14:09 libwireshark.so -> libwireshark.so.6.0.1
lrwxrwxrwx. 1 root root        21 Jul  5 14:09 libwireshark.so.6 -> libwireshark.so.6.0.1
-rwxr-xr-x. 1 root root 175362146 Jul  5 14:09 libwireshark.so.6.0.1
lrwxrwxrwx. 1 root root        19 Jul  5 14:09 libwiretap.so -> libwiretap.so.5.0.1
lrwxrwxrwx. 1 root root        19 Jul  5 14:09 libwiretap.so.5 -> libwiretap.so.5.0.1
-rwxr-xr-x. 1 root root   1760476 Jul  5 14:09 libwiretap.so.5.0.1
lrwxrwxrwx. 1 root root        18 Jul  5 14:09 libwsutil.so -> libwsutil.so.6.0.0
lrwxrwxrwx. 1 root root        18 Jul  5 14:09 libwsutil.so.6 -> libwsutil.so.6.0.0
-rwxr-xr-x. 1 root root    413792 Jul  5 14:09 libwsutil.so.6.0.0
drwxr-xr-x. 3 root root        20 Jul  1 11:37 wireshark

SharkPy expects Wireshark plugins to be in site.getsitepackages/sharkPy/64_bit_libs/plugins. Looks like this on my system.

[me@localhost ~]$ ls -l /usr/lib64/python2.7/site-packages/sharkPy/dissect/64_bit_libs/plugins/
total 6200
-rw-rw-r--. 1 root root     967 Jul  5 21:08 docsis.la
-rw-rw-r--. 1 root root  823445 Jul  5 21:08 docsis.so
-rw-rw-r--. 1 root root     979 Jul  5 21:08 ethercat.la
-rw-rw-r--. 1 root root  317809 Jul  5 21:08 ethercat.so
-rw-rw-r--. 1 root root     973 Jul  5 21:08 gryphon.la
-rw-rw-r--. 1 root root  204008 Jul  5 21:08 gryphon.so
-rw-rw-r--. 1 root root     955 Jul  5 21:08 irda.la
-rw-rw-r--. 1 root root  156485 Jul  5 21:08 irda.so
-rw-rw-r--. 1 root root     949 Jul  5 21:08 m2m.la
-rw-rw-r--. 1 root root   59554 Jul  5 21:08 m2m.so
-rw-rw-r--. 1 root root     955 Jul  5 21:08 mate.la
-rw-rw-r--. 1 root root  305747 Jul  5 21:08 mate.so
-rw-rw-r--. 1 root root     961 Jul  5 21:08 opcua.la
-rw-rw-r--. 1 root root  717950 Jul  5 21:08 opcua.so
-rw-rw-r--. 1 root root     979 Jul  5 21:08 profinet.la
-rw-rw-r--. 1 root root 1199366 Jul  5 21:08 profinet.so
-rw-rw-r--. 1 root root     991 Jul  5 21:08 stats_tree.la
-rw-rw-r--. 1 root root   46019 Jul  5 21:08 stats_tree.so
-rw-rw-r--. 1 root root     973 Jul  5 21:08 unistim.la
-rw-rw-r--. 1 root root  285718 Jul  5 21:08 unistim.so
-rw-rw-r--. 1 root root     991 Jul  5 21:08 wimaxasncp.la
-rw-rw-r--. 1 root root  184343 Jul  5 21:08 wimaxasncp.so
-rw-rw-r--. 1 root root     961 Jul  5 21:08 wimax.la
-rw-rw-r--. 1 root root     997 Jul  5 21:08 wimaxmacphy.la
-rw-rw-r--. 1 root root  196662 Jul  5 21:08 wimaxmacphy.so
-rw-rw-r--. 1 root root 1766674 Jul  5 21:08 wimax.so


##TO BUILD/INSTALL

In sharkPy download dir: sudo ./setup.py install.
