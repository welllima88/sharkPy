/* print.c
 * Gilbert Ramirez <gram@alumni.rice.edu>
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
 * sharkPyPrint.c is a modified version of code found in print.c, code compiled
 * as a shared lib that exposes dissection and object export interfaces to sharkPy
 * Python modules. sharkPy extends functionality and modifies tshark.
 *
 * Modifications: Mark Landriscina<mlandri1@jhu.edu>
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include <epan/packet-range.h>
#include <epan/print.h>
#include <epan/charsets.h>
#include <wsutil/filesystem.h>
#include <wsutil/ws_version_info.h>
#include <epan/ftypes/ftypes-int.h>

#include "sharkPy.h"

/*
 * Must be set to function that will export
 * data from C-env to python-env.
 */
extern export_attributes copy_out_attribute;

static int proto_data = -1;

static const guint8 *get_field_data(GSList *src_list, field_info *fi);
static gchar *get_field_hex_value(GSList *src_list, field_info *fi);
static void proto_tree_protobuf( proto_node *node, gpointer data );

static gchar*
get_field_hex_value(GSList *src_list, field_info *fi)
{
    const guint8 *pd;

    if (!fi->ds_tvb)
        return NULL;

    if (fi->length > tvb_captured_length_remaining(fi->ds_tvb, fi->start)) {
        return g_strdup("field length invalid!");
    }

    /* Find the data for this field. */
    pd = get_field_data(src_list, fi);

    if (pd) {
        int        i;
        gchar     *buffer;
        gchar     *p;
        int        len;
        const int  chars_per_byte = 2;

        len    = chars_per_byte * fi->length;
        buffer = (gchar *)g_malloc(sizeof(gchar)*(len + 1));
        buffer[len] = '\0'; /* Ensure NULL termination in bad cases */
        p = buffer;
        /* Print a simple hex dump */
        for (i = 0 ; i < fi->length; i++) {
            g_snprintf(p, chars_per_byte+1, "%02x", pd[i]);
            p += chars_per_byte;
        }
        return buffer;
    } else {
        return NULL;
    }
}

/*
 * Find the data source for a specified field, and return a pointer
 * to the data in it. Returns NULL if the data is out of bounds.
 */
/* XXX: What am I missing ?
 *      Why bother searching for fi->ds_tvb for the matching tvb
 *       in the data_source list ?
 *      IOW: Why not just use fi->ds_tvb for the arg to tvb_get_ptr() ?
 */

static const guint8 *
get_field_data(GSList *src_list, field_info *fi)
{
    GSList   *src_le;
    tvbuff_t *src_tvb;
    gint      length, tvbuff_length;
    struct data_source *src;

    for (src_le = src_list; src_le != NULL; src_le = src_le->next) {
        src = (struct data_source *)src_le->data;
        src_tvb = get_data_source_tvb(src);
        if (fi->ds_tvb == src_tvb) {
            /*
             * Found it.
             *
             * XXX - a field can have a length that runs past
             * the end of the tvbuff.  Ideally, that should
             * be fixed when adding an item to the protocol
             * tree, but checking the length when doing
             * that could be expensive.  Until we fix that,
             * we'll do the check here.
             */
            tvbuff_length = tvb_captured_length_remaining(src_tvb,
                                                 fi->start);
            if (tvbuff_length < 0) {
                return NULL;
            }
            length = fi->length;
            if (length > tvbuff_length)
                length = tvbuff_length;
            return tvb_get_ptr(src_tvb, fi->start, length);
        }
    }
    g_assert_not_reached();
    return NULL;  /* not found */
}

gboolean proto_tree_write_protobuf( epan_dissect_t *edt, FILE *fh )
{

        pack_data data;
        static guint32 uniqueId = 1; /* ids start at 1. Therefore, a value of 0 represents an uninitialized value. */

        if( NULL == edt || NULL == fh ) {
                fprintf( stderr,
                         "proto_tree_write_protobuf failed. Input param set to NULL: edt set to %p; fh set to %p.\n",
                         edt, fh);
                return FALSE;
        }

        data.level = 0;
        data.fh = fh;
        data.success = TRUE;
        data.src_list = edt->pi.data_src;
        data.edt = edt;
        data.id = &uniqueId;
        data.parentId = uniqueId;

        proto_tree_children_foreach( edt->tree, proto_tree_protobuf, &data );

        return data.success;
}

static void proto_tree_protobuf( proto_node *node, gpointer data )
{

    field_info *fi = PNODE_FINFO(node);
    pack_data *pdata = (pack_data*) data;
    guint32 idx = 0;
    gchar *label_ptr = NULL;
    guint8 *data_ptr = NULL;
    gchar *fstring = NULL;
    guint32 level = 0;
    guint32 position = 0;
    guint32 id = *pdata->id;
    guint32 parentId = pdata->parentId;
    export_type type;
    attribute attr = {0};
    attribute *attr_ptr = &attr;

    /* assorted temp buffers and the such */
    gchar         label_str[ITEM_LABEL_LENGTH];

   /*
    * Preliminaries
    */
    g_assert( fi );
    g_assert( pdata );

    /*
     * Increment id counter. Increments static var in calling function.
     */
    *pdata->id += 1;

    /*
     * Node Level
     */
    level = pdata->level;
	attr_ptr->level = level;
	idx++;

    /*
     * Node type
     */

    if( fi->hfinfo->id == hf_text_only ) {

        type = EXPORTED_TEXT_LABEL;


    } else if (fi->hfinfo->id == proto_data) {

        type = EXPORTED_UNINTERPRETED;

    } else {

        if ( ( fi->hfinfo->type == FT_PROTOCOL ) &&
            ( fi->hfinfo->id != proto_expert ) )  {

            type = EXPORTED_PROTOCOL;

        } else {

            type = EXPORTED_FIELD;
        }
    }
    attr_ptr->type = type;
	idx++;

	attr_ptr->ftype = fi->hfinfo->type;
	idx++;

	if ( fi->hfinfo->type != FT_NONE && fi->hfinfo->type != FT_PROTOCOL )
	{
		fstring = fvalue_to_string_repr(&fi->value, FTREPR_DISPLAY, fi->hfinfo->display, NULL);
	}

	if ( NULL != fstring && strlen( fstring )>0 )
	{
		attr_ptr->fvalue=fstring;
		idx++;
	}

	/* Node Id and Id of its parent (if any) */
	attr_ptr->id = id;
	idx++;

	attr.parent_id = parentId;
	idx++;

	/*
	 * Get labels/test descriptions/text representations of data
	 */

    if ( NULL != fi->hfinfo->abbrev)
    {
        attr_ptr->abbrev= (gchar *)fi->hfinfo->abbrev;
        idx++;
    }

    if ( NULL != fi->hfinfo->name)
    {
        attr_ptr->name=(gchar *)fi->hfinfo->name;
        idx++;
    }

    if ( NULL != fi->hfinfo->blurb)
    {
        attr_ptr->blurb=(gchar *)fi->hfinfo->blurb;
        idx++;
    }

    /*
     * Get data (if present)
     */

    if (fi->rep) {
        label_ptr = fi->rep->representation;
    } else {
        label_ptr = label_str;
        proto_item_fill_label(fi, label_str);
    }

    if( NULL != label_ptr )
    {
        attr_ptr->representation = label_ptr;
        idx++;
    }

    /* the raw data */
    if( 0 < fi->length )
    {
        data_ptr = ( guint8 *) get_field_data(pdata->src_list, fi);
    }

    if( NULL != data_ptr )
    {
        attr_ptr->data = get_field_hex_value(pdata->src_list, fi);
        idx++;
    }

    if ( EXPORTED_UNINTERPRETED != type ) {
		/* Identify and set offset */
		position = fi->start;

		if ( node->parent && node->parent->finfo &&
		   ( fi->start < node->parent->finfo->start ) ) {

				position = node->parent->finfo->start + fi->start;

		}

		attr_ptr->offset = position;
		idx++;
    }

    if ( ( fi->tree_type < -1 ) || ( fi->tree_type >= num_tree_types ) )
    {
        fprintf(stderr,
                        "Dissection tree field information error. Failed validation.\n" );
                pdata->success = FALSE;
        goto done;
    }

    /*
     * Note if current attribute is top-level frame. This is only time
     * when parent_id == id.
     */
    if (attr_ptr->parent_id == attr_ptr->id)
    {
        attr_ptr->start = TRUE;
    }

    copy_out_attribute(attr_ptr);

   /*
    * Iterate over all child-nodes, rinse and repeat. Skipped if error
    * occurs in parent node.
    */
    if ( node->first_child != NULL ) {
        pdata->level++;
        pdata->parentId = id;
        proto_tree_children_foreach( node, proto_tree_protobuf, pdata );
        pdata->level--;
        pdata->parentId = parentId; /* reset parent id value to this stack-frame's value*/
    }

done:
        /*
         * Free heap allocated memory. Data has been written out and buffers
         * are no longer required.
         */
        if ( NULL != fstring )
        {
                g_free( fstring );
                fstring = NULL;
        }
        if ( NULL != attr_ptr->data)
        {
        	g_free(attr_ptr->data);
        }

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
