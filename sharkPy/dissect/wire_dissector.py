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
# wire_dissector.py
#
# sharkPy author: Mark Landriscina
# Created on: Feb 1, 2016
#
# sharkPy is a Python adaptation of Tshark implemented as a Python module
# using Wireshark shared libs, Python ctypes, and new interface code, both
# C and Python.
#
# sharkPy module leverages ctypes to interface with precompiled Wireshark libs 
# as well as new C-code to record/track packet dissection tree structures.
# Python module code receives dissection tree node data via ctype
# funciton calls and Python callback function called from within C-code. Python
# module recreates dissection tree logical relationships presenting them to module
# callers as native Python objects. 
#
# wire_dissector.py is called to parse network packets from a live capture. This
# file and the code contained herein is released under the same license/terms as is 
# Wireshark. See description above.


from file_dissector import *

class wire_dissector(file_dissector):
    pass
    