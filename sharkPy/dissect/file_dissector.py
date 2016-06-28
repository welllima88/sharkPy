#!/usr/bin/python

############################################################################
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
# file_dissector.py
#
# sharkPy author: Mark Landriscina
# Created on: Feb 1, 2016
#
# sharkPy is a Python adaptation of Tshark implemented as a Python module
# using Wireshark shared libs, Python ctypes, and new interface code, both
# C and Python.
#
# sharkPy module leverages ctypes to interface with precompiled Wireshark libs 
# as well as new C-code to record/track packet dissection tree structure.
# Python module code receives dissection tree node data via ctype
# funciton calls and Python callback function called from within C-code. Python
# module recreates dissection tree logical relationships presenting them to module
# callers as native Python objects. 
#
# file_dissector.py is called to parse network packets from a capture file. This
# file and the code contained herein is released under the same license/terms as is 
# Wireshark. See description above.


import sys
import os,ctypes,re, site
from multiprocessing import Process
from multiprocessing import Queue as pQueue


#################################################################################################
# class opaque:
#
# Opaque pointer to C-objects.
class opaque(ctypes.Structure):
    pass
#################################################################################################
# class export_type:
#
# Node/attribute types used in sharkPy. Mostly same as is seen in Wireshark.
class export_type (object):
        NODE_TYPE = 0
        ID=1
        PARENT_ID=2
        PROTOCOL=3
        FIELD=4
        TEXT_LABEL=5
        UNINTERPRETED=6
        DATA=7
        OFFSET=8
        LEVEL=9
        NAME=10
        ABBREV=11
        BLURB=12
        STRINGS=13
        REPRESENTATION=14,
        FTYPE=15,
        FVALUE=16

#################################################################################################
# class attribute:
#
#Interfaces with c-code. Returned from callback function. As such it is a utility class
#and users should never see objects created from this class definition.
class attribute(ctypes.Structure):
    _fields_ = [  ("abbrev", ctypes.c_char_p),
                  ("name", ctypes.c_char_p),
                  ("blurb", ctypes.c_char_p),
                  ("representation", ctypes.c_char_p),
                  ("fvalue", ctypes.c_char_p),
                  ("data", ctypes.c_char_p),
                  ("level",ctypes.c_uint32),
                  ("id",ctypes.c_uint32),
                  ("parent_id", ctypes.c_uint32),
                  ("offset", ctypes.c_int),
                  ("type", ctypes.c_uint8),
                  ("ftype", ctypes.c_uint8),
                  ("start", ctypes.c_uint)]

byparent={}
byself={}
roots={}

#################################################################################################
# class item:
#
# This is the object type used for node attributes. Certainly could be better named, I supose.
# C-code executes Python callback function to export data as an attribute object (above class). 
# Attribute data elements are used to create an item object.
class item(object):
    
    ftype_desc = ["FT_NONE",
          "FT_PROTOCOL",
          "FT_BOOLEAN",
          "FT_UINT8",
          "FT_UINT16",
          "FT_UINT24",
          "FT_UINT32",
          "FT_UINT40",
          "FT_UINT48",
          "FT_UINT56",
          "FT_UINT64",
          "FT_INT8",
          "FT_INT16",
          "FT_INT24",
          "FT_INT32",
          "FT_INT40",
          "FT_INT48",
          "FT_INT56",
          "FT_INT64",
          "FT_FLOAT",
          "FT_DOUBLE",
          "FT_ABSOLUTE_TIME",
          "FT_RELATIVE_TIME",
          "FT_STRING",
          "FT_STRINGZ", 
          "FT_UINT_STRING", 
          "FT_ETHER",
          "FT_BYTES",
          "FT_UINT_BYTES",
          "FT_IPv4",
          "FT_IPv6",
          "FT_IPXNET",
          "FT_FRAMENUM", 
          "FT_PCRE", 
          "FT_GUID", 
          "FT_OID", 
          "FT_EUI64",
          "FT_AX25",
          "FT_VINES",
          "FT_REL_OID",
          "FT_SYSTEM_ID",
          "FT_STRINGZPAD", 
          "FT_FCWWN",
          "FT_NUM_TYPES"]
    
    def __init__(self,abbrev='',
                 name='',
                 blurb='',
                 representation='',
                 fvalue=None,
                 data='',
                 level=0,
                 id=0,
                 parent_id=0,
                 type=0,
                 ftype=0,
                 start=False,
                 offset=0):
        self.abbrev=abbrev
        self.name=name
        self.blurb=blurb
        self.representation=representation
        self.fvalue=fvalue
        self.data=data
        self.level=level
        self.id=id
        self.parent_id=parent_id
        self.type=type
        self.ftype=ftype
        if (len(item.ftype_desc) > self.ftype):
            self.ftype_desc=item.ftype_desc[ftype]
        else:
            raise RuntimeError("Received unknown ftype: %d" %self.ftype)
        self.start=start
        self.offset=offset
        
    def __str__(self):
        
        offset=(self.level *2)+1
        indent=' '*offset
        
        rtn=''
        rtn+=indent+"abbrev:     %s.\n"%self.abbrev
        rtn+=indent+"name:       %s.\n"%self.name
        rtn+=indent+"blurb:      %s.\n"%self.blurb
        rtn+=indent+"fvalue:     %s.\n"%self.fvalue
        rtn+=indent+"level:      %d.\n"%self.level
        rtn+=indent+"offset:     %d.\n"%self.offset
        rtn+=indent+"ftype:      %d.\n"%self.ftype
        rtn+=indent+"ftype_desc: %s.\n"%self.ftype_desc
        rtn+=indent+"repr:       %s.\n"%self.representation
        rtn+=indent+"data:       %s.\n"%self.data
        
        return rtn

#################################################################################################
# class node:
#
# Dissection tree node. This is the object type that most callers will work with. It can represent
# protocol dissetion root for a packet dissection tere. Can also represent one tree element. Typical
# tree kinda stuff here.
#
# a node consists of an item named 'attribute'. and a node list named children. 'attribute' is a disctionary
# of node's data elements indexed by the 'abbrev' element. 'children' is a list of nodes child nodes.
class node(object):
    
    def __init__(self, attributes):
        self.attributes=attributes
        self.children=[]
    def __str__(self):
        offset=self.attributes.level *2
        indent=' '*offset
        rtn = indent+"Node Attributes: \n"+str(self.attributes)
        rtn += "\n"+indent+"Number of child nodes: "+str(len(self.children))+"\n"
        for n in xrange(len(self.children)):
            rtn+=' '+indent+str(self.children[n].attributes.abbrev)+"\n"
        rtn +="\n"

        return rtn

#################################################################################################
# class file_dissector:
#
# Objects of this type do all the hard work. An entire capture file is parsed/dissected by one
# file_dissector. This is done in its own child process and should not be used directly. 
# Instantiating a file_dissector object intiates a capture file dissection. Caller receieves a list
# of nodes, one for each packet in the original capture file. The root node is the 'frame' node
# all other nodes are children of frame either directly or indirectly. Each node in the dissection
# tree is identified by its abbrev attribute, in general..
class file_dissector(object):
    
    def __init__(self, wireshark_plugin_dir=None, lib_directories=[]):
        

        self.nl_lib_path=None
        self.pcap_lib_path=None
        self.gcrypt_lib_path=None

        self.wireshark_plugin_dir=None
        self.wireshark_lib_path=None
        self.wiretap_lib_path=None
        self.wsutil_lib_path=None
        self.sharkPy_lib_path=None
        
        self.nllib=None
        self.pcaplib=None
        self.gcryptlib=None
        
        self.wiresharklib=None
        self.wiretaplib=None
        self.wsutillib=None
        self.sharkPylib=None
        
        self.init_state=None
        self.decode_as=None
        self.open_capture_file=None
        self.read_next=None
        self.close_capture_file=None
        
        self.SAVE_ATTR = ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(attribute))
        self.copy_out_attr=self.SAVE_ATTR(self.save_attr)
        
        self.open_capture_file=None
        self.read_next=None
        self.close_capture_file=None
        self.init_attr=None
        self.decode_as=None
        self.copy_out_attr=None
        
        self.current_dir=os.getcwd()

        #configure module
        self.set_env(wireshark_plugin_dir)
        self.set_libs(lib_directories)
        self.set_api()
                
        self.byparent={}
        self.byself={}
        self.roots={}
        self.root_list=[]
        
    def save_attr(self, in_attr):
        global byparent
        global byself
        global roots
            
        new_item=item(in_attr.contents.abbrev,
                      in_attr.contents.name,
                      in_attr.contents.blurb,
                      in_attr.contents.representation,
                      in_attr.contents.fvalue,
                      in_attr.contents.data,
                      in_attr.contents.level,
                      in_attr.contents.id,
                      in_attr.contents.parent_id,
                      in_attr.contents.type,
                      in_attr.contents.ftype,
                      in_attr.contents.start,
                      in_attr.contents.offset)
        
        #make node from incoming attribute
        nxt=node(new_item)
        if(nxt.attributes.parent_id not in self.byparent.keys()):
            self.byparent[nxt.attributes.parent_id]=[]
        
        #group node id attributes by common parent_id
        self.byparent[nxt.attributes.parent_id].append(nxt.attributes.id)
    
        #index each node by its id attribute
        self.byself[nxt.attributes.id]=nxt

       
    def set_api(self):

        libs=[self.nl_lib_path,
              self.pcap_lib_path,
              self.gcrypt_lib_path,
              self.wiretap_lib_path,
              self.wsutil_lib_path,
              self.wireshark_lib_path,
              self.sharkPy_lib_path]
        
        for lib in libs:
            if(lib is None):
                raise RuntimeError("Module libraries not configured.")

        self.nllib=ctypes.CDLL(self.nl_lib_path, mode=ctypes.RTLD_GLOBAL)
        self.pcaplib=ctypes.CDLL(self.pcap_lib_path, mode=ctypes.RTLD_GLOBAL)
        self.gcryptlib=ctypes.CDLL(self.gcrypt_lib_path, mode=ctypes.RTLD_GLOBAL)

        self.wsutillib=ctypes.CDLL(self.wsutil_lib_path, mode=ctypes.RTLD_GLOBAL)            
        self.wiretaplib=ctypes.CDLL(self.wiretap_lib_path, mode=ctypes.RTLD_GLOBAL)
        self.wiresharklib=ctypes.CDLL(self.wireshark_lib_path,mode=ctypes.RTLD_GLOBAL)
        self.sharkPylib=ctypes.CDLL(self.sharkPy_lib_path, mode=ctypes.RTLD_GLOBAL)
        
        #copy out attribute via callback
        self.init_attr=self.sharkPylib.init_attr
        self.init_attr.argtypes=[ctypes.POINTER(attribute), ctypes.POINTER(attribute)]
        self.init_attr.restype=None
        
        #set-up state
        self.init_state=self.sharkPylib.init_state
        self.init_state.argtypes=[self.SAVE_ATTR]
        self.init_state.restype=None        
        
        #functionality for opening capture file
        self.open_capture_file=self.sharkPylib.open_capture_file
        self.open_capture_file.argtypes=[ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(opaque))]
        self.open_capture_file.restype=ctypes.c_int
        
        #packet processing/dissection functionality
        self.read_next=self.sharkPylib.read_next
        self.read_next.argtypes=None
        self.read_next.restype=ctypes.c_uint;
        
        #all capture files must be close
        self.close_capture_file=self.sharkPylib.close_capture_file
        self.close_capture_file.argtypes=None
        self.close_capture_file.restype=ctypes.c_bool
        
        #decode as
        self.decode_as=self.sharkPylib.decode_as
        self.decode_as.argtypes=[ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p]
        self.restype=None
        
        self.copy_out_attr=self.SAVE_ATTR(self.save_attr)
    
    def set_env(self,wireshark_plugin_dir=None):
        #Get wireshark plug-in directory
        #Use value passed in during class init if defined.
        #Else use WIRESHARK_PLUGIN_DIR env variable if defined.
        if(wireshark_plugin_dir is not None and not os.path.isdir(wireshark_plugin_dir)):
            raise RuntimeError("Wireshark plug-in directory not found at %s"%wireshark_plugin_dir)
        
        elif(wireshark_plugin_dir is not None and os.path.isdir(wireshark_plugin_dir)):
            self.wireshark_plugin_dir=wireshark_plugin_dir
            os.environ["WIRESHARK_PLUGIN_DIR"]=self.wireshark_plugin_dir

        elif(wireshark_plugin_dir is None):
            os.environ["WIRESHARK_PLUGIN_DIR"]=site.getsitepackages()[0]+'sharkPy/64_bit_libs/plugins/1.8.10/'


    def set_libs(self, lib_directories=[]):
        
        #Find wireshark and other shared libraries required for module
        #First, check directories in lib_directories list if not empty
        #Else, check standard lib directories on OS.
        libnl=None
        libpcap=None
        libgcrypt=None
        libwiretap=None
        libwsutil=None
        libwireshark=None
        libsharkPy=None
            
        for each_dir in lib_directories:
            if(not os.path.isdir(each_dir)):
                raise RuntimeError("Path %s not found. Check path and try again."%each_dir)

                        
            names = [name for name in os.listdir(each_dir)
                    if os.path.isfile(os.path.join(each_dir,name))]
            
            for name in names:
                
                if (re.search(r'libnl\.so', name) is not None):
                    if(libnl is None):
                        libnl=os.path.join(each_dir,name)
                    else:
                        sz_a=os.stat(os.path.join(each_dir,name))
                        sz_b=os.stat(libnl)
                        if(sz_a.st_size > sz_b.st_size):
                            libnl=os.path.join(each_dir,name)

                elif (re.search(r'libpcap\.so', name) is not None):
                    if(libpcap is None):
                        libpcap=os.path.join(each_dir,name)
                    else:
                        sz_a=os.stat(os.path.join(each_dir,name))
                        sz_b=os.stat(libpcap)
                        if(sz_a.st_size > sz_b.st_size):
                            libpcap=os.path.join(each_dir,name)

                elif (re.search(r'libgcrypt\.so', name) is not None):
                    if(libgcrypt is None):
                        libgcrypt=os.path.join(each_dir,name)
                    else:
                        sz_a=os.stat(os.path.join(each_dir,name))
                        sz_b=os.stat(libgcrypt)
                        if(sz_a.st_size > sz_b.st_size):
                            libgcrypt=os.path.join(each_dir,name)
                            
                elif (re.search(r'libwiretap\.so', name) is not None):
                    if(libwiretap is None):
                        libwiretap=os.path.join(each_dir,name)
                    else:
                        sz_a=os.stat(os.path.join(each_dir,name))
                        sz_b=os.stat(libwiretap)
                        if(sz_a.st_size > sz_b.st_size):
                            libwiretap=os.path.join(each_dir,name)
                            
                elif (re.search(r'libwsutil\.so\.6', name) is not None):
                    if(libwsutil is None):
                        libwsutil=os.path.join(each_dir,name)
                    else:
                        sz_a=os.stat(os.path.join(each_dir,name))
                        sz_b=os.stat(libwsutil)
                        if(sz_a.st_size > sz_b.st_size):
                            libwsutil=os.path.join(each_dir,name)

                                         
                elif (re.search(r'libwireshark\.so', name) is not None):
                    if(libwireshark is None):
                        libwireshark=os.path.join(each_dir,name)
                    else:
                        sz_a=os.stat(os.path.join(each_dir,name))
                        sz_b=os.stat(libwireshark)
                        if(sz_a.st_size > sz_b.st_size):
                            libwireshark=os.path.join(each_dir,name)                

                elif (re.search(r'dissect\.so', name) is not None):
                    if(libsharkPy is None):
                        libsharkPy=os.path.join(each_dir,name)
                    else:
                        sz_a=os.stat(os.path.join(each_dir,name))
                        sz_b=os.stat(libsharkPy)
                        if(sz_a.st_size > sz_b.st_size):
                            libsharkPy=os.path.join(each_dir,name)                

        if(libnl is None):
            libnl = ctypes.cdll.find_library("libnl")
            if(libnl is None):
                raise RuntimeError("Could not locate libnl.")
            
        if(libpcap is None):
            libpcap = ctypes.cdll.find_library("libpcap")
            if(libpcap is None):
                raise RuntimeError("Could not locate libpcap.")

        if(libgcrypt is None):
            libgcrypt = ctypes.cdll.find_library("libgcrypt")
            if(libgcrypt is None):
                raise RuntimeError("Could not locate libgcrypt.")

        if(libwiretap is None):
            libwiretap = ctypes.cdll.find_library("libwiretap")
            if(libwiretap is None):
                raise RuntimeError("Could not locate libwiretap.")
            
        if(libwsutil is None):
            libwsutil = ctypes.cdll.find_library("libwsutil")
            if(libwsutil is None):
                raise RuntimeError("Could not locate libwsutil.")
  
        if(libwireshark is None):
            libwireshark = ctypes.cdll.find_library("libwireshark")
            if(libwireshark is None):
                raise RuntimeError("Could not locate libwireshark.")
            
        if(libsharkPy is None):
            libsharkPy = ctypes.cdll.find_library("dissect")
            if(libsharkPy is None):
                raise RuntimeError("Could not locate dissect.")

        #Set class library variables now that the libs have been located.
        self.nl_lib_path=libnl
        self.pcap_lib_path=libpcap
        self.gcrypt_lib_path=libgcrypt
        self.wireshark_lib_path=libwireshark
        self.wiretap_lib_path=libwiretap
        self.wsutil_lib_path=libwsutil
        self.sharkPy_lib_path=libsharkPy

    def create_heirarchy(self,):
        for p_id in self.byparent.keys():
            parent=self.byself[p_id]
            
            #save node references for all root nodes
            if parent.attributes.start and p_id not in self.roots.keys():
                self.roots[p_id]=parent
                self.root_list.append(parent)
                
            childlist=self.byparent[p_id]
            for c_id in childlist:
                child=self.byself[c_id]
                
                if p_id != c_id:
                    parent.children.append(child)
    
def walk_print(a_node):
    print a_node
    for each in a_node.children:
        walk_print(each)
            
def collect_proto_ids(start_node, id_dict):
    
    if id_dict is None:
        raise AttributeError("Must pass in a dictionary object to collect ids")
    
    if start_node.attributes.abbrev not in id_dict.keys():
        id_dict[start_node.attributes.abbrev]=[]
    
    id_dict[start_node.attributes.abbrev].append(start_node)
    for each_child in start_node.children:
        collect_proto_ids(each_child, id_dict)

# MOST people should only really care about this function!!! 
# This function creates new child process that carries out detailed packet dissection for
# an entire capture file. Each capture file MUST be processed in its own child process. 
# After sucessful processing this function receives results as a list of dissection trees, one
# tree for each packet in capture file.
def cap_file_dissection(capture_file_path, decode_as_list=[], dtimeout=None, is_daemon=True):

    sharedQ=pQueue()
    decodeAs=decode_as_list

    try:
        #carry out dissections and return results as a dissect object
        p=Process(target=run_in_new_proc,args=(sharedQ, capture_file_path ,decodeAs))
        
        p.daemon=is_daemon
        p.start()
        if(dtimeout is not None):
            p.join(dtimeout)

    except Exception as e:
        print e.message, e.args
        raise e
        
    try:
        
        d=sharedQ.get(timeout=dtimeout)
        sharedQ.close()

        if p.is_alive():
            p.terminate()
            p.join()
            raise RuntimeError("Child process terminated due to timeout.")


    except Exception as e:
        raise e

    return (d,p)

def configure():

    #Require env variable pointing to install directory for wireshark plugins

    if "WIRESHARK_PLUGIN_DIR" not in os.environ.keys():
        raise ValueError("WIRESHARK_PLUGIN_DIR environmental variable not defined.")


#It's quite difficult to find/address memory leaks in Wireshark's
#code base, so dissections are always run in their own child proc.
#After dissection is complete and results are returned to caller,
#the dissection subproc terminates. At a minimum, this prevents
#memory leaks from accumulating across multiple capture files.
def run_in_new_proc(sharedProcQ, pcap_path, decode_as=None):


    if pcap_path is None:
        raise ValueError("Did not provide pcap file path.")

    #verify pcap file exists
    if(not os.path.exists(pcap_path)):
        raise ValueError("Could not find file: %s"%pcap_path)
    
    if(not os.path.isfile(pcap_path)):
        raise ValueError(" Exists, but not a file: %s"%pcap_path)
       
    #non-standard lib paths
    lib_directories=[site.getsitepackages()[0],site.getsitepackages()[0]+'/sharkPy/dissect/64_bit_libs']

    file_path=pcap_path.encode('utf_8','strict')
    
    d=None

    try:
        d = file_dissector(None,lib_directories)
        configure()

        ctx=ctypes.pointer(ctypes.pointer(opaque()))
        if ctx is None:
            raise RuntimeError("Python failed to create new context.")

        d.init_state(d.copy_out_attr)
        
        if( decode_as is not None and len(decode_as)>0):
            
            for command in decode_as:
            
                if( len(command) != 3):
                    raise ValueError("'decode_as' takes a tuple list: table_name, numberical_selector list, decode_as_proto.")
                
                if( 0 == len(command[1] ) ):
                    raise ValueError("Expected list as second element of decode_as tuple, list with length > 0.")
                
                for port in command[1]:
                
                    if (not d.decode_as(command[0],port,command[2])):
                        raise RuntimeError("Failed to set 'decode_as' option: %s, %d, %s"%[command[0],port,command[2]])
    
        if 0 != d.open_capture_file(file_path,ctx):
            raise RuntimeError("Failed to open capture file, %s."%file_path)
        
        while(True):
            read_next_rtn=d.read_next()
            
            #End of file
            if( 0 == read_next_rtn):
                break
            
            #Protocol processing error
            if(2 == read_next_rtn):
                raise RuntimeError("Failed to process packet.")
                break
            
        d.create_heirarchy()

        #Return dissected packets to caller
        sorted_rtn_list=sorted( d.root_list, key=lambda node: node.attributes.id ) 
        sharedProcQ.put(sorted_rtn_list)
        sys.exit(0)
        
    #Exception will be re-raised in main parent process 
    except Exception as e:
        sharedProcQ.close()
        raise e

#TEST main#####TEST main#####TEST maim########TEST main#####TEST main#####TEST main#####TEST maim########TEST main
if __name__=='__main__':
    
    #set decode options
    decodeAs=([ ("tcp.port", [7771] ,"ssl") ])

    try:
        #run dissection in its own subprocess
        rst=cap_file_dissection("/root/Desktop/chrome_single_session_hostname_sf.pcap", decodeAs, None, True)
    except Exception as e:
        print e.message, e.args
        sys.exit()

    proc_handle=rst[1]
    pkts=rst[0]
    
    for each in pkts:

        #walk and print ordered list starting at root nodes
        walk_print(each)


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
