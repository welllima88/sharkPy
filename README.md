
#SharkPy is

Current version: beta 0.1

A python module to dissect, analyze, and interact with network packet data as native Python objects using Wireshark and libpcap capabilities. sharkPy dissect modules extend and otherwise modify Wireshark's tshark. SharkPy packet injection module wraps useful libpcap functionality.<br/>

SharkPy comes with three modules that allows one to explore, create, and/or modify packet data and (re)send data over network. This is all done within python program or interactive python session.<br/>

1. sharkPy.file_dissector -- dissect capture file packets using Wireshark's dissection libraries and present detailed packet dissections to caller as native Python objects.<br/>

2. sharkPy.wire_dissector -- capture packets from interface and dissect captured packets using Wireshark's dissection libraries. Presents packets to callers as native Python objects.<br/>

3. sharkPy.wire_writer -- write arbitrary data to specified network interface using libpcap functionality. Currently, sharkPy users are responsible for correctly building packets that are transmitted using this module's functionality. <br/>

Modules are written such that sharkPy commands are non-blocking. Command results are provided to caller on-demand.

##Design Goals

1. Deliver dissected packet data to callers as native python objects.<br/>

2. Provide functionality within a Python environment, either a python program or interactive python session. <br/>

3. Make commands non-blocking whenever reasonable providing command results to caller on-demand.<br/>

4. Be easy to understand and use assuming one understands Wireshark and python basics.<br/>

5. Pack functionality into a small number of commands.<br/>

6. Build and install as little C-code as possible by linking to preexisting Wireshark shared libs.<br/>

SharkPy is provided "as-is" with NO WARRANTIES expressed or implied under GPLv2. Use at your own risk.

##Why sharkPy?

SharkPy has a long-term goal of segmenting Wireshark's incredible diversity of capabilities into a set of shared libraries that are smaller, more modular, more easily compiled and linked into other projects. This goal seperates sharkPy from other similar efforts that endeavor to marry Wireshark/tshark and Python. 

The first step is provide Wireshark/tshark capabilities as Python modules that can be compiled/linked outside of Wireshark's normal build process. This has been achieved at least for some linux environments/distros. Next step is to expand to a broader range of linux distros and Windows improving stability along the way. Once this is completed and sharkPy's capabilities are similar to those provided by tshark, the sharkPy project devs will start the process of segmenting the code base as described above.

#HOW-TO

## sharkPy API -- examples in following sections

<b>dissect_file(file_path, timeout=10, options=[]):</b> dissect packet capture file and return dissected packets as native python objects<br/>
    -- file_path: path to capture file<br/>
    -- timeout: how long to wait (in seconds) before dissection attempt fails<br/>
    -- options a set of options for file dissection. Options are disopt.DECODE_AS, disopt.NAME_RESOLUTION.<br/>
    -- RETURNS: List of packet dissections as described below.<br/>
    
<b>walk_print(root_node):</b> Starting at root node of dissection tree, print representation of node, then do same for each child recursively.<br/>
    -- root_node: starting node in dissection tree to starting printing<br/>
    -- RETURNS None.<br/>
    
<b>collect_proto_ids(root_node, pkt_dict):</b> create dictionary representation of packet dissection using the 'abbrev' attribute as key.<br/>
    -- root_node: starting point in packet dissection tree where operation starts.<br/>
    -- pkt_dict: An empty dictionary that function will populate.<br/>
    -- RETURNS None.<br/>
    
<b>dissect_wire(interface, options=[], timeout=None):</b> collect packets from interface delivering packet dissections when requested using get_next function.<br/>
    -- name of interface to capture from.<br/>
    -- collection and dissection options. Options are disopt.DECODE_AS, disopt.NAME_RESOLUTION, and disopts.NOT_PROMISCUOUS.<br/>
    -- timeout: amount of time (in seconds) to wait before start capture fails.<br/>
    -- RETURNS tuple (p, exit_event, shared_queue).<br/>
        --p: dissection process handle.<br/>
        --exit_event: event handler used to signal that collection should stop.<br/>
        --shared_queue: shared queue that dissector returns dissection trees into.<br/>
        --NOTE: users should not directly interact with these return objects. Instead returned tuple is passed into get_next and close functions as input param.<br/>
        
<b>get_next(dissect_process,timeout=None):</b> get next available packet dissection from live capture.<br/>
    -- dissect_process: tuple returned from dissect_wire.<br/>
    -- timeout: amount to time to wait (in seconds) before operation timesout.<br/>
    -- RETURNS root node of packet dissection tree.<br/>
    
<b>close(dissect_process):</b> stop and clean up from live capture.<br/>
    -- dissect_process: tuple returned from dissect_wire.<br/>
    -- RETURNS None.<br/>
    -- NOTE: close MUST be called on each capture session.
    
<b>wire_writer(write_interface_list):</b> wire_writer contructor. Used to write arbitrary data to interfaces.<br/>
    -- write_interface_list: list of interface names to write to.<br/>
    -- RETURNS: wire_writer object.<br/>
        -- wire_writer.cmd: pass a command to writer.<br/>
            --wr.cmd(command=wr.WRITE_BYTES, command_data=data_to_write , command_timeout=2)<br/>
            --wr.cmd(command=wr.SHUT_DOWN_ALL,command_data=None,command_data=2)<br/>
            --wr.cmd(command=wr.SHUT_DOWN_NAMED, command_data=interface_name, command_data=2)<br/>
        -- wire_writer.get_rst(timeout=1): returns tuple (success/failure, number_of_bytes_written)<br/>

<b>do_funct_walk(root_node, funct, aux=None):</b> recursively pass each node in dissection tree (and aux) to function. Depth first walk.<br/>
    -- root_node: node in dissection tree that will be the first to be passed to function.<br/>
    -- funct: function to call.<br/>
    -- aux: optional auxilliary variable that will be passed in as parameter as part of each function call.<br/>
    -- RETURNS None.<br/>
    
<b>get_node_by_name(root_node, name):</b> finds and returns a list of dissection nodes in dissection tree with a given name (i.e., 'abbrev').<br/>
     -- root_node: root of dissection tree being passed into function.<br/>
     -- name: Name of node used as match key. Matches again 'abbrev' attribute.<br/>
     -- RETURNS: a list of nodes in dissection tree with 'abbrev' attribute that matches name. NOTE: abbrev attribute is not necessarily unique in a given dissection. tree. This is the reason that this function returns a LIST of matching nodes.<br/>
     
<b>get_node_data_details(node):</b> Returns a tuple of values that describe the data in a given dissection node.<br/>
    -- node: node that will have its details provided.<br/>
    -- RETURNS: returns tuple, (data_len,first_byte_index, last_byte_index, data, binary_data).<br/>
        -- data_len: number of bytes in node's data.<br/>
        -- first_byte_index: byte offset from start of packet where this node's data starts.<br/>
        -- last_byte_index: byte offset from start of packet where this node's data ends.<br/>
        -- data: string representation of node data.<br/>
        -- binary_data: binary representation of node data.<br/>
    

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
 
### Short-cut for finding a node by name:<br/>
val_list=sharkPy.get_node_by_name(sorted_rtn_list[0], 'ip')<br/>

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

### Get useful information about a dissection node's data<br/>
\>>> data_len, first_byte_offset, last_byte_offset, data_string_rep, data_binary_rep=sharkPy.get_node_data_details(pkt)<br/>

\>>> print data_len<br/>
54<br/>

\>>> print first_byte_offset<br/>
0<br/>

\>>> print last_byte_offset<br/>
53<br/>

\>>> print data_string_rep<br/>
005056edfe68000c29....<rest edited out><br/>

\>>> print binary_string_rep<br/>
<prints binary spleg, edited out><br/>


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

