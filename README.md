# sharkPy

Current version: beta 0.1

A python module to dissect, analyze, and interact with network packet data as native Python objects using Wireshark and libpcap capabilities. sharkPy dissect modules extend and otherwise modify Wireshark's tshark. SharkPy packet injection and pcap file writing modules wrap useful libpcap functionality.

SharkPy comes with six modules that allows one to explore, create, and/or modify packet data and (re)send data over network, and write (possibly modified) packets to a new pcap output file. This is all done within python program or interactive python session.

 1. `sharkPy.file_dissector` -- dissect capture file packets using Wireshark's dissection libraries and present detailed packet dissections to caller as native Python objects.

 2. `sharkPy.wire_dissector` -- capture packets from interface and dissect captured packets using Wireshark's dissection libraries. Presents packets to callers as native Python objects.

 3. `sharkPy.file_writer` -- write (possibly modified) packets to a new output pcap file. For example, one can dissect packet capture file using `sharkPy.file_dissector`, create new packets based on the packets in the dissected file, and then write new/modified packets to an output pcap file.

 4. `sharkPy.wire_writer` -- write arbitrary data (e.g. modified packets) to specified network interface using libpcap functionality. Currently, sharkPy users are responsible for correctly building packets that are transmitted using this module's functionality.

 5. `sharkPy.utils` -- a set of utility functions

 6. `sharkPy.protocol_blender` -- protocol specific convenience functions. Currently contains functions for ipv4 and tcp over ipv4. 

SharkPy is provided "as-is" with NO WARRANTIES expressed or implied under GPLv2. Use at your own risk.


## Versioning

current: `beta 0.1` - flesh out desired functionality and api
next:    `beta 0.2` - refactor tshark code to modularize functionality and cross compile for Windows.


## Design Goals

 1. Deliver dissected packet data to callers as native python objects.

 2. Provide functionality within a Python environment, either a python program or interactive python session. 

 3. Make commands non-blocking whenever reasonable providing command results to caller on-demand.

 4. Be easy to understand and use assuming one understands Wireshark and python basics.

 5. Pack functionality into a small number of commands.

 6. Build and install as little C-code as possible by linking to preexisting Wireshark shared libs.


## Why sharkPy?

SharkPy has a long-term goal of segmenting Wireshark's incredible diversity of capabilities into a set of shared libraries that are smaller, more modular, more easily compiled and linked into other projects. This goal seperates sharkPy from other similar efforts that endeavor to marry Wireshark/tshark and Python. 

The first step is provide Wireshark/tshark capabilities as Python modules that can be compiled/linked outside of Wireshark's normal build process. This has been achieved at least for some linux environments/distros. Next step is to expand to a broader range of linux distros and Windows improving stability along the way. Once this is completed and sharkPy's capabilities are similar to those provided by tshark, the sharkPy project devs will start the process of segmenting the code base as described above.


# HOW-TO

## sharkPy API -- examples in following sections

### Dissecting packets from file

**`dissect_file(file_path, options=[], timeout=10)`:** collect packets from packet capture file delivering packet dissections when requested using `get_next_from_file` function.
 - name of packet capture file.
 - collection and dissection options. Options are `disopt.DECODE_AS` and `disopt.NAME_RESOLUTION`.
 - timeout: amount of time (in seconds) to wait before file open fails.
 - RETURNS tuple `(p, exit_event, shared_pipe)`:
     - `p`: dissection process handle.
     - `exit_event`: event handler used to signal that collection should stop.
     - `shared_pipe`: shared pipe that dissector returns dissection trees into.
     - _NOTE:_ users should not directly interact with these return objects. Instead returned tuple is passed into `get_next_from_file` and `close_file` functions as input param.

**`get_next_from_file(dissect_process,timeout=None)`:** get next available packet dissection.
 - `dissect_process`: tuple returned from the `dissect_file` function.
 - `timeout`: amount to time to wait (in seconds) before operation timesout.
 - RETURNS root node of packet dissection tree.

**`close_file(dissect_process)`:** stop and clean up.
 - `dissect_process`: tuple returned from the `dissect_file` function.
 - RETURNS `None`.
 - _NOTE:_ `close_file` MUST be called on each session.


### Dissecting packets from wire

**`dissect_wire(interface, options=[], timeout=None)`:** collect packets from interface delivering packet dissections when requested using get_next function.
 - name of interface to capture from.
 - collection and dissection options. Options are `disopt.DECODE_AS`, `disopt.NAME_RESOLUTION`, and `disopt.NOT_PROMISCUOUS`.
 - timeout: amount of time (in seconds) to wait before start capture fails.
 - RETURNS tuple `(p, exit_event, shared_queue)`.
     - `p`: dissection process handle.
     - `exit_event`: event handler used to signal that collection should stop.
     - `shared_queue`: shared queue that dissector returns dissection trees into.
     - _NOTE:_ users should not directly interact with these return objects. Instead returned tuple is passed into `get_next_from_wire` and `close_wire` functions as input param.

**`get_next_from_wire(dissect_process,timeout=None)`:** get next available packet dissection from live capture.
 - `dissect_process`: tuple returned from the `dissect_wire` function.
 - `timeout`: amount to time to wait (in seconds) before operation timesout.
 - RETURNS root node of packet dissection tree.

**`close_wire(dissect_process)`:** stop and clean up from live capture.
 - `dissect_process`: tuple returned from the `dissect_wire` function.
 - RETURNS `None`.
 - _NOTE:_ `close_wire` MUST be called on each capture session.


### Writing data/packets on wire or to file

**`wire_writer(write_interface_list)`:** `wire_writer` constructor. Used to write arbitrary data to interfaces.
 - `write_interface_list`: list of interface names to write to.
 - RETURNS: `wire_writer` object.
     -  `wire_writer.cmd`: pass a command to writer.
         - `wr.cmd(command=wr.WRITE_BYTES, command_data=data_to_write, command_timeout=2)`
         - `wr.cmd(command=wr.SHUT_DOWN_ALL, command_data=None, command_data=2)`
         - `wr.cmd(command=wr.SHUT_DOWN_NAMED, command_data=interface_name, command_data=2)`
     - `wire_writer.get_rst(timeout=1)`: RETURNS tuple `(success/failure, number_of_bytes_written)`

**`file_writer()`:** Creates a new `file_writer` object to write packets to an output pcap file.
 - **`make_pcap_error_buffer()`:** Creates a correctly sized and initialized error buffer. 
     - Returns error buffer.
 - **`pcap_write_file(output_file_path, error_buffer)`:** create and open new pcap output file.
     - `output_file_path`: path for newly created file.
     - `err_buffer`: error buffer object returned by `make_pcap_error_buffer()`. Any errors messages will be written to this buffer. 
     - RETURNS: `ctypes.c_void_p`, which is a context object required for other write related functions.
 - **`pcap_write_packet(context, upper_time_val, lower_time_val, num_bytes_to_write, data_to_write, error_buffer)`:** writes packets to opened pcap output file.
     - `context`: object returned by `pcap_write_file()`.
     - `upper_time_val`: packet epoch time in seconds. Can be first value in tuple returned from utility function `get_pkt_times()`.
     - `lower_time_val`: packet epoch time nano seconds remainder. Can be second value in tuple returned from utility function `get_pkt_times()`.
     - `num_bytes_to_write`: number of bytes to write to file, size of data buffer.
     - `data_to_write`: buffer of data to write.
     - `err_buffer`: error buffer object returned by `make_pcap_error_buffer()`. Any errors messages will be written to this buffer.
     - RETURNS `0` on success, `-1` on failure. Error message will be available in `err_buffer`.
 - **pcap_close(context):** MUST be called to flush write buffer, close write file, and free allocated resources.
     - `context`: object returned by `pcap_write_file()`.
     - RETURNS: `None`.


### Utility functions

**`do_funct_walk(root_node, funct, aux=None)`:** recursively pass each node in dissection tree (and aux) to function. Depth first walk.
 - `root_node`: node in dissection tree that will be the first to be passed to function.
 - `funct`: function to call.
 - `aux`: optional auxilliary variable that will be passed in as parameter as part of each function call.
 - RETURNS `None`.

**`get_node_by_name(root_node, name)`:** finds and returns a list of dissection nodes in dissection tree with a given name (i.e. 'abbrev').
 - `root_node`: root of dissection tree being passed into function.
 - `name`: Name of node used as match key. Matches again 'abbrev' attribute.
 - RETURNS: a list of nodes in dissection tree with 'abbrev' attribute that matches name.
 - _NOTE:_ 'abbrev' attribute is not necessarily unique in a given dissection tree. This is the reason that this function returns a LIST of matching nodes.

**`get_node_data_details(node)`:** Returns a tuple of values that describe the data in a given dissection node.
 - `node`: node that will have its details provided.
 - RETURNS: tuple `(data_len,first_byte_index, last_byte_index, data, binary_data)`.
     - `data_len`: number of bytes in node's data.
     - `first_byte_index`: byte offset from start of packet where this node's data starts.
     - `last_byte_index`: byte offset from start of packet where this node's data ends.
     - `data`: string representation of node data.
     - `binary_data`: binary representation of node data.

**get_pkt_times(pkt=input_packet):** Returns tuple containing packet timestamp information.
 - `pkt`: packet dissection tree returned from one of sharkPy's dissection routines.
 - RETURNS: The tuple `(epoch_time_seconds, epoch_time_nanosecond_remainder)`. These two values are required for `file_writer` instances.

**`find_replace_data(pkt, field_name, test_val, replace_with=None, condition_funct=condition_data_equals, enforce_bounds=True, quiet=True)`:** A general search, match, and replace data in packets.
 - `pkt`: packet dissection tree returned from one of sharkPy's dissection routines.
 - `field_name`: the 'abbrev' field name that will have its data modified/replaced.
 - `test_val`: data_val/buffer that will be used for comparison in matching function.
 - `replace_with`: data that will replace the data in matching dissection fields.
 - `condition_funct`: A function that returns `True` or `False` and has the prototype `condition_funct(node_val, test_val, pkt_dissection_tree)`. Default is the `condition_data_equals()` function that returns `True` if `node_val == test_val`. This is a literal byte for byte matching.
 - `enforce_bounds`: If set to `True`, enforces condition that `len(replace_with) == len(node_data_to_be_replaced)`. Good idea to keep this set to its default, which is `True`.
 - `quiet`: If set to `False`, will print error message to stdout if the target field 'abbrev' name cannot be found in packet dissection tree.
 - RETURNS: new packet data represented as a hex string or `None` if target field is not in packet.

**`condition_data_equals(node_val, test_val, pkt_dissection_tree=None)`:** A matching function that can be passed to `find_replace_data()`.
 - `node_val`: value from the dissected packet that is being checked
 - `test_val`: value that `node_val` will be compared to.
 - `pkt_dissection_tree`: entire packet dissection tree. Not used in this comparison.
 - RETURNS `True` if a byte for byte comparison reveals that `node_val == test_val`. Otherwise, returns `False`.

**`condition_always_true(node_val=None, test_val=None, pkt_dissection_tree=None)`:** A matching function that can be passed to `find_replace_data()`.
 - `node_val`: Not used in this comparison
 - `test_val`: Not used in this comparison
 - `pkt_dissection_tree`: entire packet dissection tree. Not used in this comparison.
 - RETURNS `True` ALWAYS. Useful of the only matching criteria is that the target field exists in packet dissection.


### Protocol Blender

**`ipv4_find_replace(pkt_dissection, src_match_value=None, dst_match_value=None, new_srcaddr=None, new_dstaddr=None, update_checksum=True, condition_funct=sharkPy.condition_data_equals)`:** Modifies select ipv4 fields.
 - `pkt_dissection`: packet dissection tree.
 - `src_match_value`: current source ip address to look for (in hex). This value will be replaced.
 - `dst_match_value`: current destination ip address to look for (in hex). This value will be replaced.
 - `new_srcaddr`: replace current source ip address with this ip address (in hex).
 - `new_dstaddr`: replace current destination ip address with this ip address (in hex).
 - `update_checksum`: fixup ipv4 checksum if `True` (default).
 - `condition_funct`: matching function used to find correct packets to modify.

**`tcp_find_replace(pkt_dissection, src_match_value=None, dst_match_value=None, new_srcport=None, new_dstport=None, update_checksum=True, condition_funct=sharkPy.condition_data_equals)`:** Modifies select fields for tcp over ipv4.
 - `pkt_dissection`: packet dissection tree.
 - `src_match_value`: current source tcp port to look for (in hex). This value will be replaced.
 - `dst_match_value`: current destination tcp port to look for (in hex). This value will be replaced.
 - `new_srcaddr`: replace current source tcp port with this tcp port (in hex).
 - `new_dstaddr`: replace current destination tcp port with this tcp port (in hex).
 - `update_checksum`: fixup tcp checksum if `True` (default).
 - `condition_funct`: matching function used to find correct packets to modify.


## Dissect packets in a capture file

```
>>> import sharkPy
```

### Supported options so far are `DECODE_AS` and `NAME_RESOLUTION` (use option to disable)
```
>>> in_options=[(sharkPy.disopt.DECODE_AS, r'tcp.port==8888-8890,http'), (sharkPy.disopt.DECODE_AS, r'tcp.port==9999:3,http')]
```

### Start file read and dissection.
```
>>> dissection = sharkPy.dissect_file(r'/home/me/capfile.pcap', options=in_options)
```

### Use sharkPy.get_next_from_file to get packet dissections of read packets.
```
>>> rtn_pkt_dissections_list = []
>>> for cnt in xrange(13):
...     pkt = sharkPy.get_next_from_file(dissection)
...     rtn_pkt_dissections_list.append(pkt)

Node Attributes: 
 abbrev:     frame.
 name:       Frame.
 blurb:      None.
 fvalue:     None.
 level:      0.
 offset:     0.
 ftype:      1.
 ftype_desc: FT_PROTOCOL.
 repr:       Frame 253: 54 bytes on wire (432 bits), 54 bytes captured (432 bits) on interface 0.
 data:       005056edfe68000c29....<rest edited out>

Number of child nodes: 17
 frame.interface_id
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

  Node Attributes: 
   abbrev:     frame.interface_id.
   name:       Interface id.
   blurb:      None.
   fvalue:     0.
   level:      1.
   offset:     0.
   ftype:      6.
   ftype_desc: FT_UINT32.
   repr:       Interface id: 0 (eno16777736).
   data:       None.

  Number of child nodes: 0

...<remaining edited out>
```

### Must always close sessions
```
>>> sharkPy.close_file(dissection)
```

### Take a packet dissection tree and index all nodes by their names (abbrev field) 
```
>>> pkt_dict = {}
>>> sharkPy.collect_proto_ids(rtn_pkt_dissections_list[0], pkt_dict)
```

### Here are all the keys used to index this packet dissection
```
>>> print pkt_dict.keys()
['tcp.checksum_bad', 'eth.src_resolved', 'tcp.flags.ns', 'ip', 'frame', 'tcp.ack', 'tcp', 'frame.encap_type', 'eth.ig', 'frame.time_relative', 'ip.ttl', 'tcp.checksum_good', 'tcp.stream', 'ip.version', 'tcp.seq', 'ip.dst_host', 'ip.flags.df', 'ip.flags', 'ip.dsfield', 'ip.src_host', 'tcp.len', 'ip.checksum_good', 'tcp.flags.res', 'ip.id', 'ip.flags.mf', 'ip.src', 'ip.checksum', 'eth.src', 'text', 'frame.cap_len', 'ip.hdr_len', 'tcp.flags.cwr', 'tcp.flags', 'tcp.dstport', 'ip.host', 'frame.ignored', 'tcp.window_size', 'eth.dst_resolved', 'tcp.flags.ack', 'frame.time_delta', 'tcp.flags.urg', 'ip.dsfield.ecn', 'eth.addr_resolved', 'eth.lg', 'frame.time_delta_displayed', 'frame.time', 'tcp.flags.str', 'ip.flags.rb', 'tcp.flags.fin', 'ip.dst', 'tcp.flags.reset', 'tcp.flags.ecn', 'tcp.port', 'eth.type', 'ip.checksum_bad', 'tcp.window_size_value', 'ip.addr', 'ip.len', 'frame.time_epoch', 'tcp.hdr_len', 'frame.number', 'ip.dsfield.dscp', 'frame.marked', 'eth.dst', 'tcp.flags.push', 'tcp.srcport', 'tcp.checksum', 'tcp.urgent_pointer', 'eth.addr', 'frame.offset_shift', 'tcp.window_size_scalefactor', 'ip.frag_offset', 'tcp.flags.syn', 'frame.len', 'eth', 'ip.proto', 'frame.protocols', 'frame.interface_id']
```

### Note that pkt_dict entries are lists given that 'abbrevs' are not always unique within a packet.
```
>>> val_list = pkt_dict['tcp']
```

### Turns out that 'tcp' list has only one element as shown below.
```
>>> for each in val_list:
...     print each
... 
Node Attributes: 
 abbrev:     tcp.
 name:       Transmission Control Protocol.
 blurb:      None.
 fvalue:     None.
 level:      0.
 offset:     34.
 ftype:      1.
 ftype_desc: FT_PROTOCOL.
 repr:       Transmission Control Protocol, Src Port: 52630 (52630), Dst Port: 80 (80), Seq: 1, Ack: 1, Len: 0.
 data:       cd960050df6129ca0d993e7750107d789f870000.

Number of child nodes: 15
 tcp.srcport
 tcp.dstport
 tcp.port
 tcp.port
 tcp.stream
 tcp.len
 tcp.seq
 tcp.ack
 tcp.hdr_len
 tcp.flags
 tcp.window_size_value
 tcp.window_size
 tcp.window_size_scalefactor
 tcp.checksum
 tcp.urgent_pointer
```

### Shortcut for finding a node by name:
```
>>> val_list = sharkPy.get_node_by_name(rtn_pkt_dissections_list[0], 'ip')
```

### Each node in a packet dissection tree has attributes and a child node list.
```
>>> pkt = val_list[0]
```

### This is how one accesses attributes
```
>>> print pkt.attributes.abbrev
tcp
```

```
>>> print pkt.attributes.name
Transmission Control Protocol
```

### Here's the pkt's child list
```
>>> print pkt.children
[<sharkPy.dissect.file_dissector.node object at 0x10fda90>, <sharkPy.dissect.file_dissector.node object at 0x10fdb10>, <sharkPy.dissect.file_dissector.node object at 0x10fdbd0>, <sharkPy.dissect.file_dissector.node object at 0x10fdc90>, <sharkPy.dissect.file_dissector.node object at 0x10fdd50>, <sharkPy.dissect.file_dissector.node object at 0x10fddd0>, <sharkPy.dissect.file_dissector.node object at 0x10fde50>, <sharkPy.dissect.file_dissector.node object at 0x10fded0>, <sharkPy.dissect.file_dissector.node object at 0x10fdf90>, <sharkPy.dissect.file_dissector.node object at 0x1101090>, <sharkPy.dissect.file_dissector.node object at 0x11016d0>, <sharkPy.dissect.file_dissector.node object at 0x11017d0>, <sharkPy.dissect.file_dissector.node object at 0x1101890>, <sharkPy.dissect.file_dissector.node object at 0x1101990>, <sharkPy.dissect.file_dissector.node object at 0x1101b50>]
```

### Get useful information about a dissection node's data
```
>>> data_len, first_byte_offset, last_byte_offset, data_string_rep, data_binary_rep=sharkPy.get_node_data_details(pkt)
```

```
>>> print data_len
54
```

```
>>> print first_byte_offset
0
```

```
>>> print last_byte_offset
53
```

```
>>> print data_string_rep
005056edfe68000c29....<rest edited out>
```

```
>>> print binary_string_rep
<prints binary spleg, edited out>
```

## CAPTURE PACKETS FROM NETWORK AND DISSECT THEM

### SharkPy wire_dissector provides additional NOT_PROMISCUOUS option
```
>>> in_options=[(sharkPy.disopt.DECODE_AS, r'tcp.port==8888-8890,http'), (sharkPy.disopt.DECODE_AS, r'tcp.port==9999:3,http'), (sharkPy.disopt.NOT_PROMISCUOUS, None)]
```

### Start capture and dissection. Note that caller must have appropriate permissions. Running as root could be dangerous! 
```
>>> dissection = sharkPy.dissect_wire(r'eno16777736', options=in_options)
>>> Running as user "root" and group "root". This could be dangerous.
```

### Use sharkPy.get_next_from_wire to get packet dissections of captured packets.
```
>>> for cnt in xrange(13):
...     pkt=sharkPy.get_next_from_wire(dissection)
...     sharkPy.walk_print(pkt) ## much better idea to save pkts in a list
```

### Must always close capture sessions
```
>>> sharkPy.close_wire(dissection)
```

## WRITE DATA (packets) TO NETWORK

### Create writer object using interface name
```
>>> wr = sharkPy.wire_writer(['eno16777736'])
```

### Send command to write data to network with timeout of 2 seconds
```
>>> wr.cmd(wr.WRITE_BYTES,'  djwejkweuraiuhqwerqiorh', 2)
```

### Check for failure. If successful, get return values.
```
>>> if(not wr.command_failure.is_set()):
...     print wr.get_rst(1)
... 
(0, 26) ### returned success and wrote 26 bytes. ###
```

## WRITE PACKETS TO OUTPUT PCAP FILE

### Create file writer object
```
>>> fw = file_writer()
```

### Create error buffer
```
>>> errbuf = fw.make_pcap_error_buffer()
```

### Open/create new output pcap file into which packets will be written
```
>>> outfile = fw.pcap_write_file(r'/home/me/test_output_file.pcap', errbuf)
```

### Dissect packets in an existing packet capture file.
```
>>> sorted_rtn_list = sharkPy.dissect_file(r'/home/me/tst.pcap', timeout=20)
```

### Write first packet into output pcap file.

#### Get first packet dissection
```
>>> pkt_dissection=sorted_rtn_list[0]
```

#### Acquire packet information required for write operation
```
>>> pkt_frame = sharkPy.get_node_by_name(pkt_dissection, 'frame')
>>> frame_data_length, first_frame_byte_index, last_frame_byte_index, frame_data_as_string, frame_data_as_binary = sharkPy.get_node_data_details(pkt_frame[0])
>>> utime, ltime = sharkPy.get_pkt_times(pkt_dissection)
```

#### Write packet into output file
```
>>> fw.pcap_write_packet(outfile, utime, ltime, frame_data_length, frame_data_as_binary, errbuf)
```

### Close output file and clean-up
```
>>> fw.pcap_close(outfile)
```



## Match and replace before writing new packets to output pcap file

```python
import sharkPy, binascii

test_value1 = r'0xc0a84f01'
test_value2 = r'c0a84fff'
test_value3 = r'005056c00008'

fw = sharkPy.file_writer()
errbuf = fw.make_pcap_error_buffer()
outfile = fw.pcap_write_file(r'/home/me/test_output_file.pcap', errbuf)
sorted_rtn_list = sharkPy.dissect_file(r'/home/me/tst.pcap', timeout=20)

for pkt in sorted_rtn_list:

    # do replacement
    new_str_data = sharkPy.find_replace_data(pkt, r'ip.src', test_value1, r'01010101')
    new_str_data = sharkPy.find_replace_data(pkt, r'ip.dst', test_value2, r'02020202')
    new_str_data = sharkPy.find_replace_data(pkt, r'eth.src', test_value3, r'005050505050')

    # get detains required to write to output pcap file
    pkt_frame = sharkPy.get_node_by_name(pkt, 'frame')
    fdl, ffb, flb, fd, fbd = sharkPy.get_node_data_details(pkt_frame[0])
    utime, ltime = sharkPy.get_pkt_times(pkt)

    if(new_str_data is None):
        new_str_data = fd

    newbd = binascii.a2b_hex(new_str_data)
    fw.pcap_write_packet(outfile, utime, ltime, fdl, newbd, errbuf)

fw.pcap_close(outfile)
```
