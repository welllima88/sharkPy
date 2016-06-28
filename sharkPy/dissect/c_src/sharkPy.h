/*
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
# sharkPy.h
#
# SharkPy: Python adaptation of Tshark.
# By Mark Landriscina <mlandri1@jhu.edu>
# Created on: Feb 1, 2016
#
# SharkPy is a Python adaptation of Tshark implemented as a Python module
# using Wireshark shared libs, Python ctypes, and new interface code, both
# C and Python.
#
# SharkPy module leverages ctypes to interface with precompiled Wireshark libs
# as well as new C-code to record/track packet dissection tree structure.
# Python module code receives dissection tree node data via ctype
# funciton calls and Python callback function called from within C-code. Python
# module recreates dissection tree logical relationships presenting them to module
# callers as native Python objects.
#
# file_dissector.py is called to parse network packets from a capture file. This
# file and the code contained herein is released under the same license/terms as is
# Wireshark. See description above.
 */

#ifndef PYNYWIRE_H_
#define PYNYWIRE_H_


#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>
#include <gmodule.h>

#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/report_err.h>
#include <wsutil/plugins.h>
#include <wsutil/cmdarg_err.h>


#include <epan/epan-int.h>
#include <epan.h>
#include <epan/proto.h>
#include <epan/print.h>
#include <epan/tap.h>
#include <epan_dissect.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/disabled_protos.h>
#include <epan/column.h>
#include <epan/stat_tap_ui.h>
#include <epan/print.h>
#include <epan/expert.h>
#include <epan/decode_as.h>

#include <wiretap/wtap-int.h>
#include <wiretap/wtap.h>
#include <wiretap/file_wrappers.h>

#include <log.h>
#include <timestamp.h>
#include <file.h>
#include <pcap.h>
#include <frame_tvbuff.h>
#include <capture_opts.h>
#include <capture_info.h>

#include <caputils/capture-pcap-util.h>

#define MAX_ERR_MSG 2049 /*same as tshark*/

typedef enum {
  WRITE_TEXT,   /* summary or detail text */
  WRITE_XML,    /* PDML or PSML */
  WRITE_FIELDS  /* User defined list of fields */
  /* Add CSV and the like here */
} output_action_e;


typedef struct {
    gint level;
    guint *id;
    guint parentId;
    FILE *fh;
    gboolean success;
    GSList *src_list;
    epan_dissect_t *edt;
} pack_data;

typedef struct {

	gchar *abbrev;
	gchar *name;
	gchar *blurb;
	gchar *representation;
	gchar *fvalue;
	gchar *data;
	guint32 level;
	guint32 id;
	guint32 parent_id;
	gint offset;
	guint8 type;
	guint8 ftype;
	gint start;

}attribute;

typedef enum export_type {
        EXPORTED_NODE_TYPE,
        EXPORTED_ID,
        EXPORTED_PARENT_ID,
        EXPORTED_PROTOCOL,
        EXPORTED_FIELD,
        EXPORTED_TEXT_LABEL,
        EXPORTED_UNINTERPRETED,
        EXPORTED_DATA,
        EXPORTED_OFFSET,
        EXPORTED_LEVEL,
        EXPORTED_NAME,
        EXPORTED_ABBREV,
        EXPORTED_BLURB,
        EXPORTED_STRINGS,
        EXPORTED_REPRESENTATION,
        EXPORTED_FTYPE,
        EXPORTED_FVALUE,

} export_type;

typedef enum errors{

	SHARKPY_SUCCESS,
	SHARKPY_NULL_INPUT_PARAM,
	SHARKPY_MEMORY_ALLOC_FAILED,
	SHARKPY_CAPTUREFILE_ERROR,
	SHARKPY_FILEOPEN_FAILED,
	SHARKPY_WTAPFILE_ERROR,
	SHARKPY_EDT_ERROR,
	SHARKPY_UNDEFINED

} errors;

typedef capture_file ws_context;

typedef void (*export_attributes)(attribute *exp_attribute);
export_attributes copy_out_attribute;

struct protocol_name_search{
  gchar              *searched_name;  /* Protocol filter name we are looking for */
  dissector_handle_t  matched_handle; /* Handle for a dissector whose protocol has the specified filter name */
  guint               nb_match;       /* How many dissectors matched searched_name */
};
typedef struct protocol_name_search *protocol_name_search_t;

gboolean
decode_as( char *table_name, guint numeric_selector, char *decode_as);

gboolean
proto_tree_write_protobuf( epan_dissect_t *edt, FILE *fh );

cf_status_t
open_capture_file(const char *fname, ws_context **c );

gboolean
read_next(void);

gboolean
close_capture_file(void);

void
init_attr(attribute *a, attribute *b);

void
init_state(export_attributes attr_funct);

#endif /* PYNYWIRE_H_ */
