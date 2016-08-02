
#SharkPy is

version beta1.0

A python module to dissect, analyze, and interact with network packet data as native Python objects using Wireshark and libpcap capabilities. sharkPy dissect modules extend and otherwise modify Wireshark's tshark. SharkPy packet injection module wraps useful libpcap functionality.<br/>

SharkPy comes with three modules that allows one to explore, create, and/or modify packet data and (re)send data over network. This is all done within python program or interactive python session.<br/>

1. sharkPy.file_dissector -- dissect capture file packets using Wireshark's dissection libraries and present detailed packet dissections to caller as native Python objects.<br/>

2. sharkPy.wire_dissector -- capture packets from interface and dissect captured packets using Wireshark's dissection libraries. Presents packets to callers as native Python objects.<br/>

3. sharkPy.wire_writer -- write random data to specified network interface using libpcap functionality. Currently, sharkPy users are responsible for correctly building packets that are transmitted using this module's functionality. <br/>

Modules are written such that sharkPy commands are non-blocking. Command results are provided to caller on-demand.

##Design Goals

1. Deliver dissected packet data to callers as native python objects.<br/>

2. Provide functionality within a Python environment, either a python program or interactive python session. <br/>

3. Make commands non-blocking whenever reasonable providing command results to caller on-demand.<br/>

4. Be easy to understand and use assuming one understands Wireshark and python basics.<br/>

5. Pack functionality into a small number of commands.<br/>

6. Build and install as little C-code as possible by linking to preexisting Wireshark shared libs.<br/>

SharkPy is provided "as-is" with NO WARRANTIES expressed or implied under GPLv2. Use at your own risk.


#HOW-TO

##DISSECT PACKETS IN A CAPTURE FILE

\>>> import sharkPy<br/>

### Supported options so far are DECODE_AS and NAME_RESOLUTION (use option to disable)<br/>
\>>> in_options=[(sharkPy.disopt.DECODE_AS, r'tcp.port==8888-8890,http'),(sharkPy.disopt.DECODE_AS, r'tcp.port==9999:3,http')]<br/>

### Get list of dissected packets represented as python objects<br/>
\>>> sorted_rtn_list=sharkPy.dissect_file(r'/home/me/tst.pcapng',timeout=20,options=in_options)<br/>

### Walk each packet in list and print representation of packets<br/>
\>>> for each in sorted_rtn_list:<br/>
...     sharkPy.walk_print(each)<br/>

Node Attributes: <br/>
 abbrev:     frame.<br/>
 name:       Frame.<br/>
 blurb:      None.<br/>
 fvalue:     None.<br/>
 level:      0.<br/>
 offset:     0.<br/>
 ftype:      1.<br/>
 ftype_desc: FT_PROTOCOL.<br/>
 repr:       Frame 253: 54 bytes on wire (432 bits), 54 bytes captured (432 bits) on interface 0.<br/>
 data:       005056edfe68000c29....<rest edited out><br/>

Number of child nodes: 17<br/>
 frame.interface_id<br/>
 frame.encap_type<br/>
 frame.time<br/>
 frame.offset_shift<br/>
 frame.time_epoch<br/>
 frame.time_delta<br/>
 frame.time_delta_displayed<br/>
 frame.time_relative<br/>
 frame.number<br/>
 frame.len<br/>
 frame.cap_len<br/>
 frame.marked<br/>
 frame.ignored<br/>
 frame.protocols<br/>
 eth<br/>
 ip<br/>
 tcp<br/>


  Node Attributes: <br/>
   abbrev:     frame.interface_id.<br/>
   name:       Interface id.<br/>
   blurb:      None.<br/>
   fvalue:     0.<br/>
   level:      1.<br/>
   offset:     0.<br/>
   ftype:      6.<br/>
   ftype_desc: FT_UINT32.<br/>
   repr:       Interface id: 0 (eno16777736).<br/>
   data:       None.<br/>

  Number of child nodes: 0<br/>

...<remaining edited out><br/>

\>>> pkt_dict={}<br/>

### Take a packet dissection tree and index all nodes by their names (abbrev field)<br/> 
\>>> sharkPy.collect_proto_ids(sorted_rtn_list[0],pkt_dict)<br/>

### Here are all the keys used to index this packet dissection<br/>
\>>> print pkt_dict.keys()<br/>
['tcp.checksum_bad', 'eth.src_resolved', 'tcp.flags.ns', 'ip', 'frame', 'tcp.ack', 'tcp', 'frame.encap_type', 'eth.ig', 'frame.time_relative', 'ip.ttl', 'tcp.checksum_good', 'tcp.stream', 'ip.version', 'tcp.seq', 'ip.dst_host', 'ip.flags.df', 'ip.flags', 'ip.dsfield', 'ip.src_host', 'tcp.len', 'ip.checksum_good', 'tcp.flags.res', 'ip.id', 'ip.flags.mf', 'ip.src', 'ip.checksum', 'eth.src', 'text', 'frame.cap_len', 'ip.hdr_len', 'tcp.flags.cwr', 'tcp.flags', 'tcp.dstport', 'ip.host', 'frame.ignored', 'tcp.window_size', 'eth.dst_resolved', 'tcp.flags.ack', 'frame.time_delta', 'tcp.flags.urg', 'ip.dsfield.ecn', 'eth.addr_resolved', 'eth.lg', 'frame.time_delta_displayed', 'frame.time', 'tcp.flags.str', 'ip.flags.rb', 'tcp.flags.fin', 'ip.dst', 'tcp.flags.reset', 'tcp.flags.ecn', 'tcp.port', 'eth.type', 'ip.checksum_bad', 'tcp.window_size_value', 'ip.addr', 'ip.len', 'frame.time_epoch', 'tcp.hdr_len', 'frame.number', 'ip.dsfield.dscp', 'frame.marked', 'eth.dst', 'tcp.flags.push', 'tcp.srcport', 'tcp.checksum', 'tcp.urgent_pointer', 'eth.addr', 'frame.offset_shift', 'tcp.window_size_scalefactor', 'ip.frag_offset', 'tcp.flags.syn', 'frame.len', 'eth', 'ip.proto', 'frame.protocols', 'frame.interface_id']<br/>

### Note that pkt_dict entries are lists given that 'abbrevs' are not always unique within a packet.<br/>
\>>> val_list=pkt_dict['tcp']<br/>

### Turns out that 'tcp' list has only one element as shown below.<br/>
\>>> for each in val_list:<br/>
...     print each<br/>
... <br/>
Node Attributes: <br/>
 abbrev:     tcp.<br/>
 name:       Transmission Control Protocol.<br/>
 blurb:      None.<br/>
 fvalue:     None.<br/>
 level:      0.<br/>
 offset:     34.<br/>
 ftype:      1.<br/>
 ftype_desc: FT_PROTOCOL.<br/>
 repr:       Transmission Control Protocol, Src Port: 52630 (52630), Dst Port: 80 (80), Seq: 1, Ack: 1, Len: 0.<br/>
 data:       cd960050df6129ca0d993e7750107d789f870000.<br/>

Number of child nodes: 15<br/>
 tcp.srcport<br/>
 tcp.dstport<br/>
 tcp.port<br/>
 tcp.port<br/>
 tcp.stream<br/>
 tcp.len<br/>
 tcp.seq<br/>
 tcp.ack<br/>
 tcp.hdr_len<br/>
 tcp.flags<br/>
 tcp.window_size_value<br/>
 tcp.window_size<br/>
 tcp.window_size_scalefactor<br/>
 tcp.checksum<br/>
 tcp.urgent_pointer<br/>

### Each node in a packet dissection tree has attributes and a child node list.<br/>
\>>> pkt = val_list[0]<br/>

### This is how one accesses attributes<br/>
\>>> print pkt.attributes.abbrev<br/>
tcp<br/>

\>>> print pkt.attributes.name<br/>
Transmission Control Protocol<br/>

### Here's the pkt's child list<br/>
\>>> print pkt.children<br/>
\[\<sharkPy.dissect.file_dissector.node object at 0x10fda90>,\<sharkPy.dissect.file_dissector.node object at 0x10fdb10>, \<sharkPy.dissect.file_dissector.node object at 0x10fdbd0>, \<sharkPy.dissect.file_dissector.node object at 0x10fdc90>, \<sharkPy.dissect.file_dissector.node object at 0x10fdd50>, \<sharkPy.dissect.file_dissector.node object at 0x10fddd0>, \<sharkPy.dissect.file_dissector.node object at 0x10fde50>, \<sharkPy.dissect.file_dissector.node object at 0x10fded0>, \<sharkPy.dissect.file_dissector.node object at 0x10fdf90>, \<sharkPy.dissect.file_dissector.node object at 0x1101090>, \<sharkPy.dissect.file_dissector.node object at 0x11016d0>, \<sharkPy.dissect.file_dissector.node object at 0x11017d0>, \<sharkPy.dissect.file_dissector.node object at 0x1101890>, \<sharkPy.dissect.file_dissector.node object at 0x1101990>, \<sharkPy.dissect.file_dissector.node object at 0x1101b50>]<br/>

## CAPTURE PACKETS FROM NETWORK AND DISSECT THEM

### SharkPy wire_dissector provides additional NOT_PROMISCUOUS option<br/>
\>>> in_options=[(sharkPy.disopt.DECODE_AS, r'tcp.port==8888-8890,http'),(sharkPy.disopt.DECODE_AS, r'tcp.port==9999:3,http'),(sharkPy.disopt.NOT_PROMISCUOUS,None)]<br/>

### Start capture and dissection. Note that caller must have appropriate permissions. Running as root could be dangerous! <br/>
\>>> dissection=sharkPy.dissect_wire(r'eno16777736',options=in_options)<br/>
\>>> Running as user "root" and group "root". This could be dangerous.<br/>

### Use sharkPy.get_next to get packet dissections of captured packets.<br/>
\>>> for cnt in xrange(13):<br/>
...     pkt=sharkPy.get_next(dissection)<br/>
...     sharkPy.walk_print(pkt) ##much better idea to save pkts in a list<br/>

### Must always close capture sessions<br/>
\>>> sharkPy.close(dissection)<br/>

## WRITE DATA TO NETWORK

### Create writer object using interface name<br/>
\>>> wr=sharkPy.wire_writer(['eno16777736'])<br/>

### Send command to write data to network with timeout of 2 seconds<br/>
\>>> wr.cmd(wr.WRITE_BYTES,'  djwejkweuraiuhqwerqiorh',2)<br/>

### Check for failure. If successful, get return values.
\>>> if(not wr.command_failure.is_set()):<br/>
...     print wr.get_rst(1)<br/>
... <br/>
(0, 26) ### returned success and wrote 26 bytes. ###<br/>

