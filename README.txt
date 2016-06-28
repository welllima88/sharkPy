
sharkPy: Python module to dissect, analyze, and interact with network packet data as native Python objects using Wireshark and libpcap capabilities.

sharkPy-0.3Beta: Hey this is a beta. Still shaking out the bugs, but code should still work as expected for the most part. 

Should run on newish releases of Centos and Ubuntu 64-bit Linux.  

sharkPy was created to allow users to:

1. Script network traffic analysis (dissect module, file dissector)

2. Modify collected packets and rewrite modified packets back onto the wire (write module, wire_writer)

3. Create scripts that can read/interact with live packet captures (dissect module, wire_dissector). This functionality
 is being re-written at the moment. Therefore it is not included in the provided code. 
 
A main design goal is to deliver native python objects to users as soon as possible thereby
minimizing unwanted code overhead. You can look at all the underlying code if you want to. However, you only need to
understand a couple/few commands and a couple of data structures to use this module.

 ********Important note*********** 
 Using this code to create an IPS (or other network defense programs) is NOT recommended. These modules use Wireshark dissection
 libraries which have been known to contain memory leaks and other problematic issues. Code is provided
 "as-is" with NO WARRANTIES expressed or implied.
 ********Important note*********** 

CAVEAT: A familiarity with using Wireshark is assumed. Best to learn Wireshark basics before using this module.


!!!!!!!!!!!!!!!!!!!!!Quick HOW-TO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

A. COMMANDS

1. DISSECT PACKETS IN A CAPTURE FILE

import sharkPy
from sharkPy.dissect import *

###################################################################################################
#My example capture file has SSL traffic on nonstandard port, 7771. Tell sharkPy to treat this traffic as 
#SSL. sharkPy expects a decodeAs object to be a list of tuples containing the following elements:
#("match field", [list of ports to decode as a specific protocol], "name of protocol to decode as")
###################################################################################################

decodeAs=([ ("tcp.port", [7771] ,"ssl") ])

###################################################################################################
#Dissect file at given path using specific "decode as" list. Returns a list of dissected packets
#represented as trees where the "frame" element is the root. Below, I've chosen not to provide a timeout value
#which is good, since timeouts haven't been tested yet. Also, I'm running dissection as a daemon, should almost
#always be the case. In fact, should probably remove this as an option.
###################################################################################################

rst=cap_file_dissection("/root/Desktop/packetCapture.pcap", decodeAs, None, True)

###################################################################################################
#Can get a the handle to the spawned daemon if useful for something.
###################################################################################################

proc_handle=rst[1]

###################################################################################################
#Here's the returned list of dissected packets.
###################################################################################################

pkts=rst[0]

###################################################################################################
#We can walk packet trees, printing out a representation of each packet. Note that this walks a
#data structure, so you can access all the fields that you see in the resultant print out. Useful to explore
#structures/data organization.
###################################################################################################

for each in pkts:

    #walk and print ordered list starting at root node
    walk_print(each)

###################################################################################################
#The above code is ok, but you probably care much more about the following!!!    
#More usefully, we can transform each packet tree into a Python dict where the "abbrev" fields are the keys.
#The "abbrev" fields are strings such as "ssl.record.length". These keys are the same exact values that
#you will encounter in Wireshark/Tshark.
###################################################################################################

pktDict={}
collect_proto_ids(rst[0][0], pktDict)

###################################################################################################
#Above, the first packet in my packet dissect has been indexed as pktDict. For example,
#you can print out all the keys to see data elements in the packet.
###################################################################################################

 print pktDict.keys()

################################################################################################### 
 #Returns the following list.
'''
['ssl.handshake.random', 'ssl.handshake.ciphersuite', 'eth.src_resolved', 'text', 'tcp', 'frame.time_relative', 'ssl.record.length', 'ip.version', 'ssl.handshake.sig_hash_alg_len', 'ip.dst_host', 'ip.flags.df', 'ip.checksum_good', 'tcp.analysis.bytes_in_flight', 'ip.id', 'ssl.handshake.extensions_alpn_list', 'ip.checksum', 'tcp.flags.urg', 'ip.hdr_len', 'tcp.dstport', 'tcp.checksum_bad', 'ip.dsfield.dscp', 'ip.dsfield.ecn', 'frame.time_delta_displayed', 'ssl.handshake.sig_hash_algs', 'ssl', 'tcp.option_kind', 'eth.type', 'ip.addr', 'ssl.handshake.extensions_alpn_str', 'ip.src', 'ssl.handshake', 'tcp.nxtseq', 'eth.dst', 'ssl.handshake.extensions_ec_point_formats_length', 'tcp.flags.push', 'ip.flags.mf', 'ip.proto', 'ssl.handshake.extensions_server_name_list_len', 'tcp.urgent_pointer', 'frame', 'tcp.options.type.class', 'ssl.handshake.session_id_length', 'ip.ttl', 'tcp.stream', 'ssl.handshake.sig_hash_hash', 'ssl.handshake.extensions_server_name_len', 'tcp.options.type', 'tcp.option_len', 'ssl.record', 'eth.src', 'ssl.handshake.extension.len', 'frame.time', 'ssl.handshake.extensions_status_request_exts_len', 'tcp.flags.str', 'ip.flags.rb', 'ssl.handshake.extensions_server_name_type', 'tcp.checksum_good', 'ssl.handshake.extensions_server_name', 'frame.marked', 'ssl.handshake.comp_method', 'ssl.handshake.extensions_length', 'ssl.handshake.length', 'tcp.flags.reset', 'tcp.options.timestamp.tsval', 'tcp.flags.cwr', 'eth', 'ssl.handshake.extensions_elliptic_curve', 'ssl.handshake.extensions_ec_point_format', 'ssl.handshake.extensions_status_request_responder_ids_len', 'tcp.seq', 'ip.dsfield', 'ip.src_host', 'tcp.analysis', 'frame.cap_len', 'ssl.handshake.comp_methods', 'ssl.handshake.extension.data', 'tcp.flags.ns', 'eth.lg', 'ip.host', 'tcp.window_size_scalefactor', 'ssl.handshake.cipher_suites_length', 'ssl.handshake.extensions_alpn_len', 'ip.len', 'tcp.hdr_len', 'frame.number', 'ssl.handshake.extensions_elliptic_curves', 'ssl.handshake.version', 'tcp.srcport', 'tcp.checksum', 'ssl.handshake.extensions_elliptic_curves_length', 'frame.offset_shift', 'ssl.record.version', 'frame.len', 'frame.protocols', 'tcp.window_size', 'ip', 'tcp.ack', 'frame.encap_type', 'eth.ig', 'tcp.options.type.number', 'ssl.handshake.extension.type', 'ip.flags', 'tcp.len', 'tcp.flags.res', 'ssl.handshake.type', 'frame.ignored', 'tcp.options.type.copy', 'ssl.handshake.extensions_alpn_str_len', 'eth.dst_resolved', 'tcp.flags.ack', 'frame.time_delta', 'ip.frag_offset', 'eth.addr_resolved', 'ip.dst', 'tcp.flags.fin', 'ssl.handshake.extensions_status_request_type', 'ip.checksum_bad', 'tcp.window_size_value', 'ssl.handshake.random_time', 'tcp.options', 'tcp.flags', 'tcp.flags.ecn', 'ssl.handshake.comp_methods_length', 'ssl.record.content_type', 'eth.addr', 'ssl.handshake.sig_hash_sig', 'tcp.flags.syn', 'ssl.handshake.sig_hash_alg', 'tcp.port', 'frame.time_epoch', 'ssl.handshake.ciphersuites', 'tcp.options.timestamp.tsecr']
'''
###################################################################################################

###################################################################################################
#How do I use this? Ok, let's say that I want to access the 'ip.host' field in a given packet.
#Do this.
###################################################################################################

ipHost = pktDict['ip.host']
print ipHost

###################################################################################################
#REALLY IMPORTANT DETAIL HERE: ip.host is a list, since Wireshark abbrevs are not always unique. See below.
#At some point this WILL bite you in the ass. You have been warned!
#
#!!See!! ipHost is, in fact, a list. This is the result of the above print command.
#The print command above returns the following
'''
[<sharkPy.dissect.file_dissector.node object at 0x7fb917fde890>, <sharkPy.dissect.file_dissector.node object at 0x7fb917fdeb10>]
'''
###################################################################################################

###################################################################################################
#Let's print out each of the ipHost list elements.
###################################################################################################

for each in ipHost:
    print each

###################################################################################################    
#Here's the result. Check this out! Each returned tree node has a dict of **ATTRIBUTES** that can also be directly accessed.
'''
  Node Attributes: 
   abbrev:     ip.host.
   name:       Source or Destination Host.
   blurb:      None.
   fvalue:     111.1.1.11.
   level:      1.
   offset:     26.
   ftype:      23.
   ftype_desc: FT_STRING.
   repr:       Source or Destination Host: 111.1.1.11.
   data:       6f01010b.

  Number of child nodes: 0


  Node Attributes: 
   abbrev:     ip.host.
   name:       Source or Destination Host.
   blurb:      None.
   fvalue:     222.2.2.22.
   level:      1.
   offset:     30.
   ftype:      23.
   ftype_desc: FT_STRING.
   repr:       Source or Destination Host: 222.2.2.22.
   data:       de020216.

  Number of child nodes: 0
'''
###################################################################################################

###################################################################################################
#We can directly access the fValues of each node as follows.
###################################################################################################

fVal=ipHost[0].attributes.fvalue
print fVal

###################################################################################################
#Above results in the following output:
'''
111.1.1.11
'''
###################################################################################################

2. WRITE DATA (bytes) ON THE WIRE

Not much to this. Super easy.

import sharkPy
from sharkPy.write import *

###################################################################################################
# Create a wire-writer object that will write to the 'eth5' interface. Multiple interfaces
# can be listed since wire_writer accepts a list of interface names. 
###################################################################################################

wr=wire_writer(['eth5'])

###################################################################################################
# Write the bytes corresponding to the ascii string '  djwejkweuraiuhqwerqiorh'. Time out is set to 2 seconds
###################################################################################################

wr.cmd(wr.WRITE_BYTES,'  djwejkweuraiuhqwerqiorh',2)

###################################################################################################
# Get result of WRITE_BYTES command with timeout of 1 second. Note that this should
# be placed in a 'try-except' block. Attempting to get a result without a command 
#(i.e. the status queue is empty) will return an exception.
###################################################################################################

print wr.get_rst(1)

###################################################################################################
# The above print statement returns. Returns (status, number of bytes written)
# This returned SUCCESS (0) and 26 as number of bytes written.
###################################################################################################
'''
(0, 26)
'''



B. Data structures

The 'cap_file_dissection' command returns a Python list of dissected packet structures. Each packet
is represented as a TREE OF NODES. A 'node' corresponds to a Wireshark field or protocol. The hierarchy
is a little different than Wireshark in that THIS MODULE sets the 'Frame' node as the tree root and
all other nodes are decedents of the 'Frame' node. Wireshark treats 'Frame' as a protocol at the same
level as other packet protocol nodes. (I like my approach better, but other reasonable people will 
disagree. The Wireshark design requires another 'packet' node type to be the tree root.) 

Each node has an attribute dictionary that contains node details accessible by attribute names:
abbrev, name, blurb, fvalue, level, offset, ftype, ftype_desc, representation, data.

Each node also contains a python list of child nodes

This is an example of a 'Frame' (root) of a dissection tree:

Node Attributes: 
 abbrev:     frame.
 name:       Frame.
 blurb:      None.
 fvalue:     None.
 level:      0.
 offset:     0.
 ftype:      1.
 ftype_desc: FT_PROTOCOL.
 repr:       Frame 1: 275 bytes on wire (2200 bits), 275 bytes captured (2200 bits).
 data:       000c....<rest edited out>

Number of child nodes: 17
 frame.encap_type
 frame.time
 frame.offset_shift
 frame.time_epoch
 frame.time_delta
 frame.time_delta_displayed
 frame.time_relative
 frame.number
 frame.len
 frame.cap_len
 frame.marked
 frame.ignored
 frame.protocols
 eth
 ip
 tcp
 ssl

You can see the structure of the Frame node as well as a list of all its children nodes. You can walk this 
tree as is shown example code above. HOWEVER, it is far more useful to interact with packet data as a Python
dictionary.

Remember this from above? 

'''
pktDict={}
collect_proto_ids(rst[0][0], pktDict)
'''

As you will recall, this takes the first packet in the returned packet list and indexes all packet nodes as a Python
dictionary object. This is REALLY cool, since it allows you to go directly to the data elements that you are
interested in using the node 'abbrev' fields as the dictionary keys. In other wods, no need to walk a tree.

Since 'abbrevs' are not always unique, the abbrev field indices a list of nodes. Usually, this will be a list
of one node. However, there are notable exceptions. See ip.host example.

Example: I want to access the fvalue of the first node in pktDict['ip.host'].

myfValue=pktDict['ip.host'][0].attributes['fvalue']. There you go. Easy as pie.

--pktDict['ip.host'] --> give me the list of nodes indexed by 'ip.host'
--pktDict['ip.host'][0] --> give me the fist element of the list of nodes indexed by 'ip.host'
--pktDict['ip.host'][0].attributes['fvalue'] --> give me the fvalue of the first element of the node list indexed by 'ip.host'.

Woot.


