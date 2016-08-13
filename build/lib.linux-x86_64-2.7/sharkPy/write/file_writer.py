#!/usr/bin/python

# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

###########################################################################
#
# file_writer.py
#
# author: Mark Landriscina
# Created on: Jul 31, 2016
#
# file_writer writes capture packet bytes to specified dump file.
# This file and the code contained herein is released under the same 
# license/terms as is Wireshark. See description above.
#
############################################################################


import ctypes,ctypes.util,os,re,site,sys
from Queue import Queue
from threading import Thread, Event
import binascii

#################################################################################################
# class file_writer:
#
# Class to open/create pcap dump file and write packets into it.
#################################################################################################
class file_writer(object):

    
    def __init__(self,):
        self.interface_list=[]
        self.send_interfaces_list=[]

        self.pcaplib = None;
        self.writerlib = None
        
        self.pcap_lib_path = None
        self.writer_lib_path = None

        self.get_error_buffer_size = None
        self.pcap_close = None
        self.pcap_write_file = None
        self.pcap_write_packet = None

        #configure module library paths and set C-Python API interfaces
                #Adds site package dir to lib paths, so we can find our shared libs.
        self.slpath=[site.getsitepackages()[0]]
        self.set_libs()
        self.set_api()

    #Sets paths to required shared libs that we want to access directly with ctypes
    #Woot.
    def set_libs(self):
        libpcap=None
        libwriter=None

        for each_dir in self.slpath:
            if(not os.path.isdir(each_dir)):
                raise RuntimeError("Path %s not found. Check path and try again."%each_dir)

            names = [name for name in os.listdir(each_dir)
                    if os.path.isfile(os.path.join(each_dir,name))]
            
            for name in names:
                        
                if (re.search(r'libpcap\.so', name) is not None):
                    if(libpcap is None):
                        libpcap=os.path.join(each_dir,name)
                    else:
                        sz_a=os.stat(os.path.join(each_dir,name))
                        sz_b=os.stat(libpcap)
                        if(sz_a.st_size > sz_b.st_size):
                            libpcap=os.path.join(each_dir,name)
                            
                elif (re.search(r'write\.so', name) is not None):
                    if(libwriter is None):
                        libwriter=os.path.join(each_dir,name)
                    else:
                        sz_a=os.stat(os.path.join(each_dir,name))
                        sz_b=os.stat(libwriter)
                        if(sz_a.st_size > sz_b.st_size):
                            libwriter=os.path.join(each_dir,name)


        if(libpcap is None):
            libpcap = ctypes.util.find_library("pcap")
            if(libpcap is None):
                raise RuntimeError("Could not locate libpcap.")
            
        if(libwriter is None):
            libwriter = ctypes.util.find_library("write")
            if(libwriter is None):
                raise RuntimeError("Could not locate write.")

        self.pcap_lib_path=libpcap
        self.writer_lib_path=libwriter

    #define for ctypes the shared lib and functions that will be called.
    def set_api(self):

        libs=[self.pcap_lib_path,
              self.writer_lib_path]

        for lib in libs:
            if(lib is None):
                raise RuntimeError("Module libraries not configured.")

        self.pcaplib = ctypes.CDLL(self.pcap_lib_path, mode=ctypes.RTLD_GLOBAL)
        self.writerlib=ctypes.CDLL(self.writer_lib_path)
        
        self.get_error_buffer_size=self.writerlib.getErrorBufferSize
        self.get_error_buffer_size.argtypes=[]
        self.get_error_buffer_size.restype=ctypes.c_uint
        
        self.pcap_write_file = self.writerlib.pcap_write_file
        self.pcap_write_file.argtypes=[ctypes.c_char_p, ctypes.c_char_p]
        self.pcap_write_file.restype=ctypes.c_void_p
        
        self.pcap_write_packet = self.writerlib.pcap_write_packet
        self.pcap_write_packet.arg_types=[ctypes.c_void_p,
                                          ctypes.c_int64, 
                                          ctypes.c_int32, 
                                          ctypes.c_uint32, 
                                          ctypes.c_char_p, 
                                          ctypes.c_char_p]
        self.pcap_write_packet.restype=ctypes.c_int32
               
        self.pcap_close = self.writerlib.close_pcap_dump
        self.pcap_close.arg_types=[ctypes.c_void_p]
        self.pcap_close.restype = None

    def make_pcap_error_buffer(self,):
        err_buf_size = self.get_error_buffer_size()
        err_buf = ctypes.create_string_buffer(err_buf_size)
        return err_buf
    

#TEST main#####TEST main#####TEST maim########TEST main#####TEST main#####TEST main#####TEST maim########TEST main
if __name__=='__main__':

    import sharkPy
    
    fw=file_writer()
    errbuf=fw.make_pcap_error_buffer()
    outfile=fw.pcap_write_file(r'/home/me/test_output_file.pcap', errbuf)

    sorted_rtn_list=sharkPy.dissect_file(r'/home/me/tst.pcap',timeout=20)
    
    
    for pkt in sorted_rtn_list:
        pkt_frame = sharkPy.get_node_by_name(pkt, 'frame')
        src_eth = sharkPy.get_node_by_name(pkt, 'eth.src')
        dst_eth = sharkPy.get_node_by_name(pkt, 'eth.dst')
        
        fdl, ffb, flb, fd, fbd = sharkPy.get_node_data_details(pkt_frame[0])
        utime, ltime = sharkPy.get_pkt_times(pkt)
        
        esdl, esfb, eslb, esd, esbd = sharkPy.get_node_data_details(src_eth[0])
        eddl, edfb, edlb, edd, edbd = sharkPy.get_node_data_details(dst_eth[0])
        
        #swap dst and src eth addresses
        new_str_data=esd
        new_str_data+=edd
        new_str_data+=fd[(eslb+1)*2:]
        
        newbd = binascii.a2b_hex(new_str_data)
        
        fw.pcap_write_packet(outfile, utime,ltime,fdl,newbd,errbuf)
        
    fw.pcap_close(outfile)

