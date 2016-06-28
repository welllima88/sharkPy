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
# sharkPy.c
#
# SharkPy: Python adaptation of Tshark.
# By Mark Landriscina <mlandri1@jhu.edu>
# Created on: Feb 1, 2016
#
# SharkPy is a Python adaptation of Tshark implemented as a Python module
# using Wireshark shared libs, Python ctypes, and new interface code, both
# C and Python. Borrows heavily from Tshark code base.
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

#include "sharkPy.h"
#define _GNU_SOURCE

capture_file cfile;
errors last_error = SHARKPY_SUCCESS;
char last_error_msg[MAX_ERR_MSG+1];

/*
 * Slew of file scoped variables used to maintain dissection state.
 * Taken pretty much verbatim from Tshark code.
 */
static gboolean perform_two_pass_analysis = FALSE;
static gboolean print_packet_info = TRUE;
static gboolean line_buffered = FALSE;
static print_stream_t *print_stream = NULL;

static output_fields_t* output_fields  = NULL;
static capture_options global_capture_opts;

static guint32 cum_bytes;
static const frame_data *ref;
static frame_data ref_frame;
static frame_data *prev_dis;
static frame_data prev_dis_frame;
static frame_data *prev_cap;
static frame_data prev_cap_frame;

static char *last_field_name = NULL;
static header_field_info *last_hfinfo;
static GHashTable* prefixes = NULL;
static GHashTable *gpa_name_map = NULL;

static guint32 framenum = 0;

static errors
sharkPy_cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err);

static void
sharkPy_set_err(errors err, const char *err_msg);

static const char *
cf_open_error_message(int err, gchar *err_info, gboolean for_writing,
                      int file_type);

static gboolean
sharkPy_print_packet(capture_file *cf, epan_dissect_t *edt);

static gboolean
sharkPy_process_packet(capture_file *cf, epan_dissect_t *edt, gint64 offset, struct wtap_pkthdr *whdr,
               const guchar *pd, guint tap_flags);

static int
init_read_state(capture_file *cf);

static void
sharkPy_clean_up(void);

static const nstime_t *
sharkPy_get_frame_ts(void *data, guint32 frame_num);

static epan_t *
sharkPy_epan_new(capture_file *cf);

static void
find_protocol_name_func(const gchar *table, gpointer handle, gpointer user_data);



void
init_state(export_attributes attr_funct)
{
    setlocale(LC_ALL, "");
    init_process_policies();
    relinquish_special_privs_perm();
    framenum=0;
    timestamp_set_type(TS_UTC_WITH_YMD);
    timestamp_set_precision(TS_PREC_AUTO);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    /*
     * Plug-in loaders require that wireshark lib be loaded in Python with
     * 'wiresharklib = ctypes.CDLL(<wireshark lib path>,mode=ctypes.RTLD_GLOBAL)'
     */
    epan_register_plugin_types(); /* Types known to libwireshark */
    wtap_register_plugin_types(); /* Types known to libwiretap */
    scan_plugins();
    register_all_wiretap_modules();
    epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL);

    copy_out_attribute = attr_funct;
}

cf_status_t
open_capture_file(const gchar *fname, ws_context **c )
{

	cf_status_t rtn = SHARKPY_SUCCESS;
    int err = 0;
    gboolean list_link_layer_types = FALSE;
    volatile int in_file_type = WTAP_TYPE_AUTO;
    gchar *volatile cf_name = (gchar *)fname;
    dfilter_t *dfcode = NULL;

    if(NULL == fname||NULL == c)
    {
    	err = SHARKPY_NULL_INPUT_PARAM;
        sharkPy_set_err(rtn,"NULL input parameter to open_capture_file.");
    }

    cap_file_init(&cfile);
    list_link_layer_types = FALSE;
    cfile.dfcode = dfcode;
    print_stream = print_stream_text_stdio_new(stdout);

    if( NULL == (output_fields = output_fields_new()))
    {
        rtn=SHARKPY_FILEOPEN_FAILED;
        sharkPy_set_err(rtn,"Could not acquire new output_fields structure.");
        goto fail;
    }

    if (SHARKPY_SUCCESS != sharkPy_cf_open(&cfile, cf_name, in_file_type, FALSE, &err)) {
        rtn=SHARKPY_CAPTUREFILE_ERROR;
        sharkPy_set_err(rtn,"Failed to open capture file.");
        goto fail;
    }

    if(SHARKPY_SUCCESS != (err = init_read_state(&cfile)))
    {
        rtn=err;
        sharkPy_set_err(rtn,"Failed to initialize file read state");
        goto fail;
    }

      *c=(ws_context *)&cfile;

fail:
    return rtn;
}

/*
 * copy b-->a
 */
void
init_attr(attribute *a, attribute *b)
{
    a->id=b->id;
    a->parent_id = b->parent_id;
    a->level = b->level;
    a->type = b->type;
}

gboolean
read_next(void)
{

    gint err;
    gboolean rtn=FALSE;
    gchar *err_info = NULL;
    gint64 data_offset;
    guint tap_flags=0;

    capture_file *cf = &cfile;
    epan_dissect_t *edt = NULL;


    edt=epan_dissect_new(cf->epan, TRUE,TRUE);

    if( TRUE == (rtn = wtap_read(cf->wth, &err, &err_info, &data_offset)))
    {

        rtn = sharkPy_process_packet(cf, edt, data_offset, wtap_phdr(cf->wth),
                                     wtap_buf_ptr(cf->wth),
                                     tap_flags);

        framenum++;
     }

    if (NULL != edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }


      return rtn;
}

gboolean
close_capture_file(void)
{
    gboolean rtn=TRUE;
    capture_file *cf=&cfile;

    wtap_close(cf->wth);
    cf->wth = NULL;
    sharkPy_clean_up();

    return rtn;
}

gboolean
decode_as( char *table_name, guint numeric_selector, char *decode_as)
{
    gboolean rtn=TRUE;
    dissector_table_t table_matching;
    dissector_handle_t dissector_matching;
    struct protocol_name_search user_protocol_name;

    /*
     * Returns dissector table handle
     */
    table_matching = find_dissector_table(table_name);
    if (!table_matching) {
      rtn=FALSE;
    }

    user_protocol_name.nb_match = 0;
    user_protocol_name.searched_name = decode_as;
    user_protocol_name.matched_handle = NULL;
    dissector_table_foreach_handle(table_name, find_protocol_name_func, &user_protocol_name); /* Go and perform the search for this dissector in the this table's dissectors' names and shortnames */

    if (user_protocol_name.nb_match != 0) {
    } else {
        rtn = FALSE;
        goto fail;
    }

    dissector_matching = user_protocol_name.matched_handle;
    dissector_change_uint(table_name, numeric_selector, dissector_matching);

fail:
    return rtn;
}


header_field_info *
proto_registrar_get_byname(const char *field_name)
{
        header_field_info    *hfinfo;
        prefix_initializer_t  pi;

        if (!field_name)
                return NULL;

        if (g_strcmp0(field_name, last_field_name) == 0) {
                return last_hfinfo;
        }

        hfinfo = (header_field_info *)g_hash_table_lookup(gpa_name_map, field_name);

        if (hfinfo) {
                g_free(last_field_name);
                last_field_name = g_strdup(field_name);
                last_hfinfo = hfinfo;
                return hfinfo;
        }

        if (!prefixes)
                return NULL;

        if ((pi = (prefix_initializer_t)g_hash_table_lookup(prefixes, field_name) ) != NULL) {
                pi(field_name);
                g_hash_table_remove(prefixes, field_name);
        } else {
                return NULL;
        }

        hfinfo = (header_field_info *)g_hash_table_lookup(gpa_name_map, field_name);

        if (hfinfo) {
                g_free(last_field_name);
                last_field_name = g_strdup(field_name);
                last_hfinfo = hfinfo;
        }
        return hfinfo;
}

int
proto_registrar_get_id_byname(const char *field_name)
{
        header_field_info *hfinfo;

        hfinfo = proto_registrar_get_byname(field_name);

        if (!hfinfo)
                return -1;

        return hfinfo->id;
}


static int
init_read_state(ws_context *ctx)
{
      gint         linktype;
      int          rtn = 0;
      epan_dissect_t *edt = NULL;
      capture_file *cf=&cfile;

      wtap_phdr_init(&cf->phdr);
      linktype = wtap_file_encap(cf->wth);

      edt = epan_dissect_new(cf->epan, TRUE, TRUE);
      if( NULL == edt )
      {
          rtn=	SHARKPY_WTAPFILE_ERROR;
          sharkPy_set_err(rtn,"Could not new epan dissect session.");
      }

      framenum=0;

    return rtn;
}


static errors
sharkPy_cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
    wtap  *wth;
    gchar *err_info;
    errors rtn = SHARKPY_SUCCESS;

    wth = wtap_open_offline(fname, type, err, &err_info, perform_two_pass_analysis);
    if (wth == NULL)
    {
    	rtn = SHARKPY_FILEOPEN_FAILED;
        sharkPy_set_err(SHARKPY_FILEOPEN_FAILED,err_info);
        goto fail;
    }

    /* The open succeeded.  Fill in the information for this file. */

    /* Create new epan session for dissection. */
    epan_free(cf->epan);
    cf->epan = sharkPy_epan_new(cf);

    cf->wth = wth;
    cf->f_datalen = 0; /* not used, but set it anyway */

    /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
    cf->filename = g_strdup(fname);

    /* Indicate whether it's a permanent or temporary file. */
    cf->is_tempfile = is_tempfile;

    /* No user changes yet. */
    cf->unsaved_changes = FALSE;

    cf->cd_t      = wtap_file_type_subtype(cf->wth);
    cf->open_type = type;
    cf->count     = 0;
    cf->drops_known = FALSE;
    cf->drops     = 0;
    cf->snap      = wtap_snapshot_length(cf->wth);
    if (cf->snap == 0) {
        /* Snapshot length not known. */
        cf->has_snap = FALSE;
        cf->snap = WTAP_MAX_PACKET_SIZE;
    } else
        cf->has_snap = TRUE;

    nstime_set_zero(&cf->elapsed_time);
    ref = NULL;
    prev_dis = NULL;
    prev_cap = NULL;

    cf->state = FILE_READ_IN_PROGRESS;

    wtap_set_cb_new_ipv4(cf->wth, add_ipv4_name);
    wtap_set_cb_new_ipv6(cf->wth, (wtap_new_ipv6_callback_t) add_ipv6_name);

fail:
    return rtn;
}



static void
sharkPy_set_err(errors err, const char *err_msg)
{

    gint i=0;
	memset(last_error_msg,0,MAX_ERR_MSG+1);
    last_error = err;

    if(SHARKPY_SUCCESS == err)
    {
    	goto success;
    }

    /*
     * Determine msg size, setting upper bound to MAX_ERR_MSG.
     */
    for(i=0;i<MAX_ERR_MSG;++i)
    {
        if('\0' == err_msg[i])
        {
            break;
        }
    }

    memcpy(last_error_msg,err_msg,i-1);

success:
    return;
}

static void
sharkPy_clean_up(void)
{
    if(NULL != cfile.wth)
    {
        wtap_sequential_close(cfile.wth);
    }
    if(NULL != cfile.filename)
    {
        g_free(cfile.filename);
        cfile.filename=NULL;
    }
    if (cfile.frames != NULL) {
        free_frame_data_sequence(cfile.frames);
        cfile.frames = NULL;
    }

    last_error = SHARKPY_SUCCESS;
    memset(last_error_msg,0,MAX_ERR_MSG+1);

    epan_free(cfile.epan);
    output_fields_free(output_fields);
    output_fields = NULL;
    epan_cleanup();
}

static const nstime_t *
sharkPy_get_frame_ts(void *data, guint32 frame_num)
{
    capture_file *cf = (capture_file *) data;

    (void) cf;

    if (ref && ref->num == frame_num)
      return &ref->abs_ts;

    if (prev_dis && prev_dis->num == frame_num)
      return &prev_dis->abs_ts;

    if (prev_cap && prev_cap->num == frame_num)
      return &prev_cap->abs_ts;

    /*
    if (cf->frames) {
       frame_data *fd = frame_data_sequence_find(cf->frames, frame_num);

       return (fd) ? &fd->abs_ts : NULL;
    }
    */

    return NULL;
}


static epan_t *
sharkPy_epan_new(capture_file *cf)
{
    epan_t *epan = epan_new();

    epan->data = cf;
    epan->get_frame_ts = sharkPy_get_frame_ts;
    epan->get_interface_name = cap_file_get_interface_name;
    epan->get_user_comment = NULL;

    return epan;
}

static gboolean
sharkPy_process_packet(capture_file *cf, epan_dissect_t *edt, gint64 offset, struct wtap_pkthdr *whdr,
               const guchar *pd, guint tap_flags)
{
  frame_data      fdata;
  column_info    *cinfo;
  gboolean        passed;

  /* Count this packet. */
  cf->count++;

  passed = TRUE;

  frame_data_init(&fdata, cf->count, whdr, offset, cum_bytes);

  if (edt) {
    if (print_packet_info && (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
        gbl_resolv_flags.transport_name || gbl_resolv_flags.concurrent_dns))
      /* Grab any resolved addresses */
      host_name_lookup_process();

    /* If we're running a filter, prime the epan_dissect_t with that
       filter. */
    if (cf->dfcode)
      epan_dissect_prime_dfilter(edt, cf->dfcode);

    cinfo = NULL;

    frame_data_set_before_dissect(&fdata, &cf->elapsed_time,
                                  &ref, prev_dis);
    if (ref == &fdata) {
      ref_frame = fdata;
      ref = &ref_frame;
    }

    epan_dissect_run_with_taps(edt, cf->cd_t, whdr, frame_tvbuff_new(&fdata, pd), &fdata, cinfo);

    /* Run the filter if we have it. */
    if (cf->dfcode)
      passed = dfilter_apply_edt(cf->dfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(&fdata, &cum_bytes);

    if (print_packet_info) {

      sharkPy_print_packet(cf, edt);

      if (line_buffered)
        fflush(stdout);

      if (ferror(stdout)) {
        //show_print_file_io_error(errno);
        exit(2);
      }
    }

    /* this must be set after print_packet() [bug #8160] */
    prev_dis_frame = fdata;
    prev_dis = &prev_dis_frame;
  }

  prev_cap_frame = fdata;
  prev_cap = &prev_cap_frame;

  if (edt) {
    epan_dissect_reset(edt);
    frame_data_destroy(&fdata);
  }
  return passed;
}

static gboolean
sharkPy_print_packet(capture_file *cf, epan_dissect_t *edt)
{

    proto_tree_write_protobuf(edt, stdout);
    return !ferror(stdout);

}

/*
 * This function parses all dissectors associated with a table to find the
 * one whose protocol has the specified filter name.  It is called
 * as a reference function in a call to dissector_table_foreach_handle.
 * The name we are looking for, as well as the results, are stored in the
 * protocol_name_search struct pointed to by user_data.
 * If called using dissector_table_foreach_handle, we actually parse the
 * whole list of dissectors.
 */
static void
find_protocol_name_func(const gchar *table _U_, gpointer handle, gpointer user_data)

{
  int                     proto_id;
  const gchar            *protocol_filter_name;
  protocol_name_search_t  search_info;

  g_assert(handle);

  search_info = (protocol_name_search_t)user_data;

  proto_id = dissector_handle_get_protocol_index((dissector_handle_t)handle);
  if (proto_id != -1) {
    protocol_filter_name = proto_get_protocol_filter_name(proto_id);
    g_assert(protocol_filter_name != NULL);
    if (strcmp(protocol_filter_name, search_info->searched_name) == 0) {
      /* Found a match */
      if (search_info->nb_match == 0) {
        /* Record this handle only if this is the first match */
        search_info->matched_handle = (dissector_handle_t)handle; /* Record the handle for this matching dissector */
      }
      search_info->nb_match++;
    }
  }
}


static const char *
cf_open_error_message(int err, gchar *err_info, gboolean for_writing,
                      int file_type)
{
  const char *errmsg;
  static char errmsg_errno[1024+1];

  if (err < 0) {
    /* Wiretap error. */
    switch (err) {

    case WTAP_ERR_NOT_REGULAR_FILE:
      errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
      break;

    case WTAP_ERR_RANDOM_OPEN_PIPE:
      /* Seen only when opening a capture file for reading. */
      errmsg = "The file \"%s\" is a pipe or FIFO; pynywire can't read pipe or FIFO files in two-pass mode.";
      break;

    case WTAP_ERR_FILE_UNKNOWN_FORMAT:
      /* Seen only when opening a capture file for reading. */
      errmsg = "The file \"%s\" isn't a capture file in a format pynywire understands.";
      break;

    case WTAP_ERR_UNSUPPORTED:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" contains record data that pynywire doesn't support.\n"
                 "(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_CANT_WRITE_TO_PIPE:
      /* Seen only when opening a capture file for writing. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" is a pipe, and \"%s\" capture files can't be "
                 "written to a pipe.", wtap_file_type_subtype_short_string(file_type));
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_UNWRITABLE_FILE_TYPE:
      /* Seen only when opening a capture file for writing. */
      errmsg = "pynywire doesn't support writing capture files in that format.";
      break;

    case WTAP_ERR_UNWRITABLE_ENCAP:
      /* Seen only when opening a capture file for writing. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "pynywire can't save this capture as a \"%s\" file.",
                 wtap_file_type_subtype_short_string(file_type));
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
      if (for_writing) {
        g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                   "pynywire can't save this capture as a \"%s\" file.",
                   wtap_file_type_subtype_short_string(file_type));
        errmsg = errmsg_errno;
      } else
        errmsg = "The file \"%s\" is a capture for a network type that pynywire doesn't support.";
      break;

    case WTAP_ERR_BAD_FILE:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" appears to be damaged or corrupt.\n"
                 "(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_CANT_OPEN:
      if (for_writing)
        errmsg = "The file \"%s\" could not be created for some unknown reason.";
      else
        errmsg = "The file \"%s\" could not be opened for some unknown reason.";
      break;

    case WTAP_ERR_SHORT_READ:
      errmsg = "The file \"%s\" appears to have been cut short"
               " in the middle of a packet or other data.";
      break;

    case WTAP_ERR_SHORT_WRITE:
      errmsg = "A full header couldn't be written to the file \"%s\".";
      break;

    case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
      errmsg = "This file type cannot be written as a compressed file.";
      break;

    case WTAP_ERR_DECOMPRESS:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The compressed file \"%%s\" appears to be damaged or corrupt.\n"
                 "(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    default:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" could not be %s: %s.",
                 for_writing ? "created" : "opened",
                 wtap_strerror(err));
      errmsg = errmsg_errno;
      break;
    }
      sharkPy_set_err(SHARKPY_WTAPFILE_ERROR,errmsg);
  } else {
	  sharkPy_set_err(SHARKPY_SUCCESS,"");
  }

  return last_error_msg;
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

