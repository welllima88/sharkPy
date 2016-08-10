/* tshark.c
 *
 * Text-mode variant of Wireshark, along the lines of tcpdump and snoop,
 * by Gilbert Ramirez <gram@alumni.rice.edu> and Guy Harris <guy@alum.mit.edu>.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * sharkPy.h is a modified version of code found in tshark.c, code compiled
 * as a shared lib that exposes dissection and object export interfaces to sharkPy
 * Python modules. sharkPy extends functionality and modifies tshark.
 *
 * Modifications: Mark Landriscina<mlandri1@jhu.edu>
 */

#ifndef SHARKPY_H_
#define SHARKPY_H_

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif


#include <config.h>
#include <glib.h>
#include <gmodule.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/report_err.h>
#include <wsutil/plugins.h>
#include <wsutil/cmdarg_err.h>
#include <epan/epan-int.h>
#include <epan/epan.h>
#include <epan/proto.h>
#include <epan/tap.h>
#include <epan/epan_dissect.h>
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
#include <epan/timestamp.h>
#include <file.h>
#include <pcap.h>
#include <frame_tvbuff.h>
#include <capture_opts.h>
#include <capture_info.h>
#include <caputils/capture-pcap-util.h>

#define MAX_ERR_MSG 2049 /*same as tshark*/

typedef enum {
  WRITE_TEXT,    /* summary or detail text */
  WRITE_XML,     /* PDML or PSML */
  WRITE_FIELDS,  /* User defined list of fields */
  WRITE_PYEXPORT /* Export packet dissection */
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
		EXPORTED_FINI,

} export_type;

typedef enum errors{

        SHARKPY_FAILURE = -1,
        SHARKPY_SUCCESS = 1,

} errors;

int
run(int argc, char *argv[]);

typedef void (*export_attributes)(attribute *exp_attribute);

gboolean
proto_tree_write_protobuf( epan_dissect_t *edt, FILE *fh );

header_field_info *
proto_registrar_get_byname(const char *field_name);

int
proto_registrar_get_id_byname(const char *field_name);

void
sharkPy_set_prog_dir(const char *name);

void
set_export_function(export_attributes func);

void
init_attr(attribute *a, attribute *b);

void
stop_cap_child();

gint
get_cap_child_id();

#ifdef __cplusplus
}
#endif

#endif /* SHARKPY_H_ */
