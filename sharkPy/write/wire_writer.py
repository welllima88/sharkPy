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
# wire_writer.py
#
# writer.py author: Mark Landriscina
# Created on: Feb 1, 2016
#
# wire_writer writes arbitrary bytes to specified local interface(s).
# Assumes caller has adequate permissions. YOU HAVE BEEN WARNED. This
# file and the code contained herein is released under the same license/terms as is 
# Wireshark. See description above.
#
############################################################################


import ctypes,os,re,site,sys
from Queue import Queue
from threading import Thread, Event

#################################################################################################
# class _interface_info:
#
#Interfaces with c-code. Returned from callback function. As such it is a utility class
#and users should never see objects created from this class definition.
class _interface_info(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint),
                ("description", ctypes.c_char_p),
                ("name", ctypes.c_char_p),
                ("openable", ctypes.c_uint),
                ("datalink_types", ctypes.c_char_p)]

#################################################################################################
# class interface_info:
#
#_Creates an interface info object which is part of user API. Describes information that
# PCAP provides about a given interface.
class interface_info(object):
    def __init__(self, iface_structure):

        self.description = iface_structure.contents.description
        self.name = iface_structure.contents.name
        self.flags = iface_structure.contents.flags
        self.openable = False
        self.datalink_types = None 
        
        if(0 < iface_structure.contents.openable):
            self.openable = True
            self.datalink_types = iface_structure.contents.datalink_types

#################################################################################################
# class wire_writer_child:
#
# wire_writer_child object is run in its own thread. Main jobs are to set-up writer API and 
# write bytes to some local interface at direction of the wire_writer object that created it.
# Users should not directly create/interact with objects of this type. Wire_writer_child objects
# are leveraged/managed via their parent wire-writer object, the one that created them.
class wire_writer_child(object):

    #Class command values
    SHUT_DOWN_ALL=0
    SHUT_DOWN_NAMED=1
    WRITE_BYTES=2
    TERMINATE=3

    #Class command return values
    COMMAND_OK=0
    COMMAND_FAIL=1
    
    
    def __init__(self, lib_directories=[]):
        self.interface_list=[]
        self.send_interfaces_list=[]

        self.pcaplib = None;
        self.writerlib = None
        
        self.pcap_lib_path = None
        self.writer_lib_path = None

        self.set_interface_callback = None
        self.get_number_of_interfaces = None
        self.get_error_buffer_size = None
        self.get_interface_list = None
        self.pcap_open_live = None
        self.pcap_inject = None
        self.pcap_close = None
        
        #callback functionality to export inteface information 
        self.SAVE_IFACE = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(_interface_info))
        self.copy_out_iface=self.SAVE_IFACE(self.save_iface)

        #configure module library paths and set C-Python API interfaces
        self.set_libs(lib_directories)
        self.set_api()

    #Sets paths to required shared libs that we want to access directly with ctypes
    #Woot.
    def set_libs(self, lib_directories=[]):
        libpcap=None
        libwriter=None

        for each_dir in lib_directories:
            if(not os.path.isdir(each_dir)):
                raise RuntimeError("Path %s not found. Check path and try again."%each_dir)

        #First, look in nonstandard dirs listed by caller
        for each_dir in lib_directories:
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

        #If not found, search device default lib path
        if(libpcap is None):
            libpcap = ctypes.cdll.find_library("libpcap")
            if(libpcap is None):
                raise RuntimeError("Could not locate libpcap.")

        if(libwriter is None):
            libwriter = ctypes.cdll.find_library("write")
            if(libpcap is None):
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
        
        self.set_interface_callback = self.writerlib.setInterfaceExportCallback
        self.set_interface_callback.argtypes=[self.SAVE_IFACE]
        self.set_interface_callback.restype=None
        
        #set Python callback for C-code
        self.set_interface_callback(self.copy_out_iface)

        self.get_error_buffer_size=self.writerlib.getErrorBufferSize
        self.get_error_buffer_size.argtypes=[]
        self.get_error_buffer_size.restype=ctypes.c_uint

        self.get_number_of_interfaces=self.writerlib.getNumberOfInterfaces
        self.get_number_of_interfaces.argtypes=[ctypes.c_char_p]
        self.get_number_of_interfaces.restype=ctypes.c_int
        
        self.get_interface_info_list=self.writerlib.getInterfaceInfoList
        self.get_interface_info_list.argtypes=[ctypes.c_char_p]
        self.get_interface_info_list.restype=ctypes.c_int
        
        self.pcap_open_live = self.pcaplib.pcap_open_live
        self.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_char_p]
        self.pcap_open_live.restype = ctypes.c_void_p
        
        self.pcap_inject = self.pcaplib.pcap_inject
        self.pcap_inject.argtypes=[ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
        self.pcap_inject.restype=ctypes.c_int
        
        self.pcap_close = self.pcaplib.pcap_close
        self.pcap_close.argtypes = [ctypes.c_void_p]
        self.pcap_close.restype = None

    def save_iface(self, in_iface):
        if(in_iface is None):
            raise ValueError("_interface not provided in functional call.")
        new_iface=interface_info(in_iface)
        self.interface_list.append(new_iface)

    def make_pcap_error_buffer(self,):
        err_buf_size = self.get_error_buffer_size()
        err_buf = ctypes.create_string_buffer(err_buf_size)
        return err_buf

    def verify_send_interfaces(self, list_of_iface_names):
        err_buf = self.make_pcap_error_buffer()
        name_list=[]

        #re-kerjigger lists
        for each in self.send_interfaces_list:
            self.send_interfaces_list.remove(each)

        for each in self.interface_list:
            self.interface_list.remove(each)

        if( 0 > self.get_interface_info_list(err_buf) ):
            raise RuntimeError("Pcap error: "+str(err_buf.value))
        
        for each in self.interface_list:
            name_list.append(each.name)
        
        for each in list_of_iface_names:
            
            if (each == 'any'):
                raise ValueError("Cannot write to Psuedo-device 'any'.")

            if (each not in name_list):
                raise ValueError("Interface with name "+str(each)+" not available.")

    def open_interfaces_for_sending(self, list_of_iface_names):
        #Make error buffer
        err_buf = self.make_pcap_error_buffer()

        try:
            #Check if we can (likely) write to interface
            self.verify_send_interfaces(list_of_iface_names)
        except Exception as e:
            raise e

        #Call pcap_open_live to get interface descriptors, which
        #will be squirreled away in self.send_interfaces_list
        for each in list_of_iface_names:

            rst = self.pcap_open_live(each, 65535, 0, 0, err_buf)
            if rst is None:
                raise RuntimeError("Failed to open interface "+str(each)+". Pcap error: "+str(err_buf.value))

            #Append tuple (iface name, iface descriptor
            self.send_interfaces_list.append( (each, rst) )

    def close_sending_interfaces(self, iface_list=[]):
        #Default is to close all interfaces. However individual interfaces can be
        #closed by specifying them by name and passing those names into this function
        #in a list.
        if iface_list is None or len(iface_list) == 0:
            for each in self.send_interfaces_list:
                self.pcap_close(each[1])

        else:
            names = []
            for each in self.send_interfaces_list:
                names.append(each[0])

            for name in iface_list:
                if( name not in names ):
                    raise ValueError("Provided interface name is not open or is unknown, "+str(name))

                self.pcap_close(name)

    def write_bytes(self, bufr):
        for iface in self.send_interfaces_list:
            name=iface[0]
            ifc=iface[1]
            write_bfr=ctypes.create_string_buffer(bufr)
            try:
                rtn=self.pcap_inject(ifc, write_bfr, len(write_bfr))
            except Exception as e:
                raise e
        return rtn

    def do_command(self, cmd, cmd_data):
        rtn_status = self.COMMAND_OK
        rtn_data = None
        
        if (cmd == self.SHUT_DOWN_ALL):
            self.close_sending_interfaces()
        elif (cmd == self.SHUT_DOWN_NAMED):
            self.close_sending_interfaces(cmd_data)
        elif (cmd == self.WRITE_BYTES):
            rtn_data=self.write_bytes(cmd_data)
            if(0 > rtn_data):
                rtn_status=self.COMMAND_FAIL
        elif (cmd == self.TERMINATE):
            pass
        else:
            raise ValueError("Received unknown command with value of %d" % cmd)
        
        return((rtn_status, rtn_data))

#################################################################################################
# class wire_writer:
#
# wire_writer is the MAIN user interface to module's wire writing functionality. Eg, to write bytes to
# interface 'eth0', do this:
# 
# >>wr=wire_writer(['eth0'])                                 <--creates new wire_writer object
# >>wr.cmd(wr.WRITE_BYTES,'asdjwejkweuraiuhqwerqiorh')       <--sends command to write given bytes to interface
# >>return_val, any_return_data = wr.get_rst()               <--gets any return values from command
# >>print (return_val, any_return_data)                      <--return tuple indicates sucess (0) and that 26 bytes
#  (0, 26)                                                   of data were written to interface eth0
# >>

class wire_writer(object):
    #Class command values
    SHUT_DOWN_ALL=0
    SHUT_DOWN_NAMED=1
    WRITE_BYTES=2
    TERMINATE=3
    
    #Class command return values
    COMMAND_OK=0
    COMMAND_FAIL=1

    def __init__(self, write_interface_list):
        self.write_interface_list=write_interface_list
        self.command_queue = Queue()  #to writer child
        self.status_queue = Queue()   #fm writer child
        self.command_failure=Event()
        self.new_wire_writer(write_interface_list)

    def new_wire_writer(self, write_interface_list, is_daemon=True):

        try:
            t=Thread(target=self.run_in_new_thread, args=(write_interface_list, self.command_queue, self.status_queue, self.command_failure))
            t.daemon=is_daemon
            t.start()
            t.join(1) #without this will not see thread exceptions from main thread

        except Exception as e:
            raise e
        
    #################This is the writer code that is run in its own thread#####################
    def run_in_new_thread(self, write_interface_list, command_queue, status_queue, fail_event):
        lib_directories=[site.getsitepackages()[0],site.getsitepackages()[0]+'/sharkPy/dissect/64_bit_libs']
        wr=wire_writer_child(lib_directories)
        err_buf = wr.make_pcap_error_buffer()
        fail_event.clear()
        
        try:
            wr.open_interfaces_for_sending(write_interface_list)
        except Exception as e:
            fail_event.set()
            raise e

        while(True):

            if(fail_event.is_set()):
                break

            try:
                #thread blocks on queue.get command waiting for next command
                cmd,cmd_val=command_queue.get()

                if (self.TERMINATE == cmd):
                    command_queue.task_done()
                    break

                (status, rtn_data) = wr.do_command(cmd,cmd_val)
                command_queue.task_done()
                status_queue.put((status, rtn_data))

            #re-raise exception to command side
            except Exception as e:
                fail_event.set()
                raise e

        #close all interfaces opened by this writer
        wr.close_sending_interfaces()
    ###############################################################################################

    def cmd(self, command, command_data=None, cmd_timeout=None):
        self.command_queue.put((command, command_data), timeout=cmd_timeout)
        
    def get_rst(self,get_timeout=None):
        if self.command_failure.is_set():
            raise RuntimeError("Last command failed.")
        
        rtn=self.status_queue.get(get_timeout)
        self.status_queue.task_done()
        
        return(rtn)

#TEST main#####TEST main#####TEST maim########TEST main#####TEST main#####TEST main#####TEST maim########TEST main
if __name__=='__main__':

    wr=wire_writer(['eth5'])
    wr.cmd(wr.WRITE_BYTES,'  djwejkweuraiuhqwerqiorh',2)

    
    if(not wr.command_failure.is_set()):
        print wr.get_rst(1)
    else:
        print "write command failed."



#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# tab-width: 8
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 tabstop=8 expandtab:
# :indentSize=4:tabSize=8:noTabs=true:
#/
