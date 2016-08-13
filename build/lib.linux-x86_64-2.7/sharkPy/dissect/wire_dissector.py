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
# wire_dissector.py
#
# wire_dissector.py author: Mark Landriscina <mlandri1@jhu.edu>
# Created on: Jul 31, 2016
#
# wire_dissector reads in packets from network interface in format supported by
# wireshark and provides the wireshark dissection of packets as native Python objects.
# Assumes caller has adequate permissions. YOU HAVE BEEN WARNED. This
# file and the code contained herein is released under the same license/terms as is 
# Wireshark. See description above.
#
############################################################################

import sys, signal
import os,ctypes,ctypes.util,re, site
from multiprocessing import Process, Event
from multiprocessing import Queue as pQueue
from threading import Thread


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
        FINI=17

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


class wire_dissector(Process):
    
    def __init__(self, exit_event, sharedQueue, interface, wireshark_plugin_dir=None):
        
        Process.__init__(self)
        
        #Adds site package dir to lib paths, so we can find our shared libs.
        self.slpath=[site.getsitepackages()[0]]
        
        self.sharedQueue=sharedQueue
        self.interface=interface
        self.dumpcap_path = getDumpcapExecPath()
        self.wireshark_plugin_dir=None
        self.wireshark_lib_path=None
        self.wiretap_lib_path=None
        self.wsutil_lib_path=None
        self.sharkPy_lib_path=None
        
        self.wiresharklib=None
        self.wiretaplib=None
        self.wsutillib=None
        self.dissectlib=None
        
        self.setExport=None
        self.dissect=None
        self.stop_capture=None
        
        self.SAVE_ATTR=ctypes.CFUNCTYPE(ctypes.c_bool, ctypes.POINTER(attribute))
        self.copy_out_attr=self.SAVE_ATTR(self.save_attr)
        
        self.current_dir=os.getcwd()

        #configure module
        self.set_env(wireshark_plugin_dir)
        self.set_libs()
        self.set_api()
                
        self.byparent={}
        self.byself={}
        self.roots={}
        self.root_list=[]
        
        #When set, exit subprocess
        self.exit = exit_event

    def set_api(self):

        libs=[self.wiretap_lib_path,
              self.wsutil_lib_path,
              self.wireshark_lib_path,
              self.sharkPy_lib_path]
        
        for lib in libs:
            if(lib is None):
                raise RuntimeError("Module libraries not configured.")

        self.wsutillib=ctypes.CDLL(self.wsutil_lib_path, mode=ctypes.RTLD_GLOBAL)            
        self.wiretaplib=ctypes.CDLL(self.wiretap_lib_path, mode=ctypes.RTLD_GLOBAL)
        self.wiresharklib=ctypes.CDLL(self.wireshark_lib_path,mode=ctypes.RTLD_GLOBAL)
        self.sharkPylib=ctypes.CDLL(self.sharkPy_lib_path, mode=ctypes.RTLD_GLOBAL)
        
        self.dissect=self.sharkPylib.run
        self.dissect.arg_types=[ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)]
        self.dissect.restype=ctypes.c_int
        
        self.setExport=self.sharkPylib.set_export_function
        self.setExport.arg_types=[self.SAVE_ATTR]
        self.setExport.restype=None
        
        self.stop_capture=self.sharkPylib.stop_cap_child
        self.stop_capture.arg_types=[]
        self.stop_capture.restype=None
        
        self.get_cap_child_id=self.sharkPylib.get_cap_child_id
        self.get_cap_child_id.arg_types=[]
        self.get_cap_child_id.restype=ctypes.c_int
        
        self.setExport(self.copy_out_attr)
        
    def set_libs(self):
        
        #Find wireshark and other shared libraries required for module
        #First, check directories in lib_directories list if not empty
        #Else, check standard lib directories on OS.
        libwiretap=None
        libwsutil=None
        libwireshark=None
        libsharkPy=None
            
        for each_dir in self.slpath:
            if(not os.path.isdir(each_dir)):
                raise RuntimeError("Path %s not found. Check path and try again."%each_dir)

            names = [name for name in os.listdir(each_dir)
                    if os.path.isfile(os.path.join(each_dir,name))]
            
            for name in names:
                        
                if (re.search(r'libwiretap\.so', name) is not None):
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


        if(libwiretap is None):
            libwiretap = ctypes.util.find_library("wiretap")
            if(libwiretap is None):
                raise RuntimeError("Could not locate libwiretap.")
            
        if(libwsutil is None):
            libwsutil = ctypes.util.find_library("wsutil")
            if(libwsutil is None):
                raise RuntimeError("Could not locate libwsutil.")
  
        if(libwireshark is None):
            libwireshark = ctypes.util.find_library("wireshark")
            if(libwireshark is None):
                raise RuntimeError("Could not locate libwireshark.")
            
        if(libsharkPy is None):
            libsharkPy = ctypes.util.find_library("dissect")
            if(libsharkPy is None):
                raise RuntimeError("Could not locate dissect.")

        #Set class library variables now that the libs have been located.
        self.wireshark_lib_path=libwireshark
        self.wiretap_lib_path=libwiretap
        self.wsutil_lib_path=libwsutil
        self.sharkPy_lib_path=libsharkPy
        
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
            os.environ["WIRESHARK_PLUGIN_DIR"]=site.getsitepackages()[0]+'sharkPy/64_bit_libs/plugins'
            
    def save_attr(self, in_attr):
            
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
        
        #terminating node, process packet and deliver it to caller
        if(export_type.FINI == in_attr.contents.type):
            #Recreate node relationships using node ids and parent ids
            self.create_heirarchy()
                       
            #Pass most recently dissected packet to caller
            pkt=self.root_list[-1]
            self.sharedQueue.put(pkt)
            self.root_list.remove(pkt)
            
            #done with this packet
            return
        
        #make node from incoming attribute
        nxt=node(new_item)
                
        if(nxt.attributes.parent_id not in self.byparent.keys()):
            self.byparent[nxt.attributes.parent_id]=[]
        
        #group node id attributes by common parent_id
        self.byparent[nxt.attributes.parent_id].append(nxt.attributes.id)
    
        #index each node by its id attribute
        self.byself[nxt.attributes.id]=nxt
        
        
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
                    
class disopt(object):
    
    NOT_PROMISCUOUS=1
    DECODE_AS=2
    PKT_CNT=3
    NAME_RESOLUTION=6
    
    wire_opts={NOT_PROMISCUOUS:'-p',
               DECODE_AS:'-d',
               PKT_CNT:'-c',
               NAME_RESOLUTION:'-n'}
    
    file_opts={DECODE_AS:'-d',
               NAME_RESOLUTION:'-n'}
    
    opt_patterns={NOT_PROMISCUOUS:None,
                 DECODE_AS:r'\w+(\.[a-zA-Z]+)*==\d+([-:]\d+)?,\w+',
                 PKT_CNT:'\d+',
                 NAME_RESOLUTION:None}
                               
def walk_print(a_node):
    
    if(a_node is None):
        return
    
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
        
def getDumpcapExecPath():
    
    dirs = os.environ['PATH']
    dirlist=dirs.split(os.pathsep)
    sepr=os.path.sep
    rtnpath=None
    
    for path in dirlist:
        dlist = os.listdir(path)
        if(r'dumpcap' in dlist):
            rtnpath=path
            break
        elif(r'dumpcap.exe' in dlist):
            rtnpath=path
            break
        
    if(None == rtnpath):
        raise RuntimeError("Could not locate dumpcap executable in PATH. wire_dissect will not run")
    
    return rtnpath

def run(exit_event, shared_queue, interface, timeout, options=[]):

    fd=None
    dPath= getDumpcapExecPath()
    cmd_options=[dPath,'-i', interface,]
    
    #options is a list of tuples of the form (option, value)
    for opt in options:
        
        #Must be type currently supported.
        if(opt[0] not in disopt.wire_opts.keys()):
            raise AttributeError("Not a valid dissect_wire option:"+str(opt))
        
        opt_pattern=disopt.opt_patterns[opt[0]]
        if(opt_pattern is not None and re.match(opt_pattern, opt[1]) is None):
            raise AttributeError("Invalid option syntax:"+str(opt))
        
        cmd_options.append(disopt.wire_opts[opt[0]])
        if(opt[1] is not None):
            cmd_options.append(opt[1])
    
    try:
        fd=wire_dissector(exit_event, shared_queue, interface)
        argc = ctypes.c_int(len(cmd_options))
        myargv = ctypes.c_char_p *(len(cmd_options))
        argv = myargv()
        
        for idx in xrange(len(cmd_options)):
            argv[idx]=cmd_options[idx]
        
        Argv = ctypes.pointer(argv)
        
        t=Thread(target=fd.dissect, args=(argc, Argv))
        t.setDaemon(True)
        t.start()
                
        fd.exit.wait()
        if(fd is not None):
            fd.stop_capture()
            fd.exit.clear()

    except Exception as e:
        print e
        raise e
    
    finally:
        #We are done. Dissection process terminates freeing all its resources.
        shared_queue.cancel_join_thread()
        sys.exit(0)
 
def dissect_wire(interface, options=[], timeout=None):
    
    shared_queue = pQueue()
    exit_event=Event()
    p=None
                 
    try:
        p=Process(target=run,args=(exit_event, shared_queue, interface ,timeout, options))
        p.daemon=True
        p.start()

    except Exception as e:
        print e.message, e.args
        raise e
    
    return (p,exit_event, shared_queue)

def get_next(dissect_process,timeout=None):

    pkt=None
    timeout_secs=timeout
    shared_queue=dissect_process[2]

    try:
        pkt=shared_queue.get(timeout=timeout_secs)
    except Exception as e:
        print e
    
    return pkt
    
#MUST call close on dissect process to clean-up.
#will end up with orphaned processes otherwise.
def close(dissect_process):
    
    proc=dissect_process[0]
    exit_event=dissect_process[1]
    shared_queue=dissect_process[2]
    
    #Close shared queue
    shared_queue.close()

    #Signal child processes to exit
    exit_event.set()     
    
    
#TEST main#####TEST main#####TEST maim########TEST main#####TEST main#####TEST main#####TEST maim########TEST main
if __name__=='__main__':
    
    in_options=[(disopt.DECODE_AS, r'tcp.port==8888-8890,http'),
             (disopt.DECODE_AS, r'tcp.port==9999:3,http'),
             (disopt.NOT_PROMISCUOUS,None)]
    dissection=dissect_wire(r'eno16777736',options=in_options)
    
    if(dissection is not None):

        for cnt in xrange(13):
            pkt=get_next(dissection)
            walk_print(pkt)
            print(cnt)
        
        close(dissection)
        
        
        
