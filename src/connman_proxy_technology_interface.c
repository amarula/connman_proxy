/*
 *  Copyright 2019, Munez Bokkapatna Nayakwady <munezbn.dev@gmail.com>, All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *  Author(s)        : Munez BN <munezbn.dev@gmail.com>
 *  File             : connman_proxy_technology_interface.c
 *  Description      : Proxy interface for connman technology object
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "connman_proxy.h"
#include "connman_proxy_internal.h"

#define CONNMAN_PROXY_TECH_PARSE_PROPERTY(tech_obj, key, value) \
        if(strcmp(key, CONNMAN_PROP_NAME_STR) == 0) \
            CONNMAN_VAR_GET_STR_DUP(value, tech_obj->name) \
        else if(strcmp(key, CONNMAN_PROP_TYPE_STR) == 0) \
            CONNMAN_VAR_GET_STR_DUP(value, tech_obj->type) \
        else if(strcmp(key, CONNMAN_PROP_POWERED_STR) == 0) \
            CONNMAN_VAR_GET_BOOL(value, tech_obj->powered) \
        else if(strcmp(key, CONNMAN_PROP_CONNECTED_STR) == 0) \
            CONNMAN_VAR_GET_BOOL(value, tech_obj->connected) \
        else if(strcmp(key, CONNMAN_PROP_TETHERING_STR) == 0) \
            CONNMAN_VAR_GET_BOOL(value, tech_obj->tethering) \
        else \
        { \
            CONNMAN_LOG_WARNING("Unknown Property : %s\n", key); \
        }

/**** Static ****/

static gint
s_connman_find_technology_by_path(gpointer a, gpointer b)
{
    connman_proxy_technology_info_t *tech_obj = a;
    CONNMAN_LOG_TRACE("Matching %s vs %s\n", (char *)b, tech_obj->obj_path);
    return strcmp(b, tech_obj->obj_path);
}

static void
s_connman_proxy_tech_scan_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;

    CONNMAN_PROXY_UNUSED(user_data);
    ret = net_connman_technology_call_scan_finish (NET_CONNMAN_TECHNOLOGY(proxy), res, &error);
    if(ret == TRUE)
    {
        CONNMAN_LOG_INFO("Scan Completed...\n");
    }
    else
    {
        CONNMAN_LOG_ERROR("Scan failed : %s\n", error->message);
        g_error_free (error);
    }
}

static void
s_connman_proxy_tech_powered_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    
    CONNMAN_PROXY_UNUSED(user_data);
    ret = net_connman_technology_call_set_property_finish (NET_CONNMAN_TECHNOLOGY(proxy), res, &error);
    if(ret == TRUE)
    {
        CONNMAN_LOG_INFO("Configured Power : %s\n", user_data ? (char *)user_data :"Unknown Tech");
    }
    else
    {
        CONNMAN_LOG_ERROR("Couldnt Set Power : %s\n", error->message);
        g_error_free (error);
    }
}

/**** Hidden ****/

connman_proxy_technology_info_t *
connman_proxy_technology_find_by_path(connman_proxy_handler_t *connman_proxy_handler, const gchar *object_path)
{
    GSList *path_node = NULL;
    connman_proxy_technology_info_t *tech_obj = NULL;

    connman_return_val_if_invalid_arg(connman_proxy_handler == NULL || object_path == NULL, NULL);

    if((path_node = g_slist_find_custom(connman_proxy_handler->technologies, object_path, (GCompareFunc)s_connman_find_technology_by_path)))
        tech_obj = path_node->data;
    else
    {
        CONNMAN_LOG_WARNING("Could Not Find technology with path : %s\n", object_path);
    }

    return tech_obj;
}

void
connman_proxy_technology_cleanup(gpointer free_obj, gpointer user_data)
{
    connman_proxy_technology_info_t *tech_obj = (connman_proxy_technology_info_t *)free_obj;
    connman_return_if_invalid_arg(tech_obj == NULL);
        
    CONNMAN_PROXY_UNUSED(user_data);

    CONNMAN_PROXY_SAFE_GFREE(tech_obj->obj_path);
    CONNMAN_PROXY_SAFE_GFREE(tech_obj->name);
    CONNMAN_PROXY_SAFE_GFREE(tech_obj->type);

    g_object_unref(tech_obj->tech_proxy);

    free(tech_obj);
}

void
connman_proxy_technology_property_changed_cb(NetConnmanTechnology *object, char *name, GVariant *unboxed_value, gpointer user_data)
{
    connman_proxy_technology_info_t *tech_obj = (connman_proxy_technology_info_t *) user_data;

    connman_return_if_invalid_arg(tech_obj == NULL);

    CONNMAN_PROXY_UNUSED(object);
    CONNMAN_LOG_USER("[%s] Propert Changed : %s\n", (char *) tech_obj->obj_path, name);
    connman_proxy_util_print_g_variant(name, unboxed_value);
    CONNMAN_PROXY_TECH_PARSE_PROPERTY(tech_obj, name, unboxed_value);
}

void
connman_proxy_technology_add_new(connman_proxy_handler_t *connman_proxy_handler, gchar *obj_path, GVariant *res)
{
    GSList *path_node = NULL;
    gchar *key = NULL;
    GVariantIter iter;
    GVariant *value = NULL;
    GError *err = NULL;
    connman_proxy_technology_info_t *tech_obj = NULL;

    connman_return_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL);

    CONNMAN_LOG_TRACE("Object Path : %s\n", obj_path);
    if((path_node = g_slist_find_custom(connman_proxy_handler->technologies, obj_path, (GCompareFunc)s_connman_find_technology_by_path)))
    {
        tech_obj = path_node->data;
        CONNMAN_LOG_INFO("^^^^^^^^^^ A Technology Has Been Updated ^^^^^^^^^^ Path : %s and type %s\n", tech_obj->obj_path, tech_obj->type);
    }
    else /* We didnt find node with matching dbus object path so create a new node to add*/
    {
        if((tech_obj = g_new0(connman_proxy_technology_info_t, 1)) == NULL)
        {
            CONNMAN_LOG_ERROR("Memory Allocation Failed : %s\n", obj_path);
            return;
        }
        tech_obj->tech_proxy = net_connman_technology_proxy_new_sync(connman_proxy_handler->connection, G_DBUS_PROXY_FLAGS_NONE, CONNMAN_SERVICE, obj_path, NULL, &err);
        if(tech_obj->tech_proxy == NULL)
        {
            CONNMAN_LOG_ERROR("Could Not Connect to Service Proxy %s : %s\n", obj_path, err ? err->message : "Unknown Reason");
            if(err)
                g_error_free (err);
            g_free(tech_obj);
            return;
        }
        tech_obj->obj_path = g_strdup(obj_path);
        connman_proxy_handler->technologies = g_slist_append (connman_proxy_handler->technologies, tech_obj);
        CONNMAN_LOG_INFO("+++++++++++ A New Technology Has Been Added +++++++++++ Path : %s\n", obj_path);
    }

    /* Parse property and update */
    if(res)
    {
        g_variant_iter_init (&iter, res);
        while (g_variant_iter_next (&iter, "{sv}", &key, &value))
        {
            CONNMAN_PROXY_TECH_PARSE_PROPERTY(tech_obj, key, value);

            /*must free data for ourselves*/
            g_variant_unref (value);
            g_free (key);
        }
    }
}

void
connman_proxy_technology_remove(connman_proxy_handler_t *connman_proxy_handler, char *obj_path)
{
	GSList *path_node = NULL;
	connman_proxy_technology_info_t *tech_obj = NULL;
	
    connman_return_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL);

    if((path_node = g_slist_find_custom(connman_proxy_handler->technologies, obj_path, (GCompareFunc)s_connman_find_technology_by_path)))
    {
        tech_obj = path_node->data;
        CONNMAN_LOG_DEBUG("Found Technology Node %p with Object path %s and type %s\n", tech_obj, tech_obj->obj_path, tech_obj->type);

        connman_proxy_handler->technologies = g_slist_remove (connman_proxy_handler->technologies, tech_obj);
        connman_proxy_technology_cleanup(tech_obj, NULL);
    }
}

void
connman_proxy_technology_scan(connman_proxy_handler_t *connman_proxy_handler, char *obj_path)
{
	GSList *path_node = NULL;
	connman_proxy_technology_info_t *tech_obj = NULL;
	
    connman_return_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL);

    if((path_node = g_slist_find_custom(connman_proxy_handler->technologies, obj_path, (GCompareFunc)s_connman_find_technology_by_path)))
    {
        tech_obj = path_node->data;
        CONNMAN_LOG_DEBUG("Found Technology Node %p with Object path %s and type %s\n", tech_obj, tech_obj->obj_path, tech_obj->type);
        net_connman_technology_call_scan(tech_obj->tech_proxy, NULL, (GAsyncReadyCallback)s_connman_proxy_tech_scan_cb, connman_proxy_handler);
    }
    else
    {
        CONNMAN_LOG_ERROR("Invalid Technology Object To Scan : %s\n", obj_path);
    }
}

void
connman_proxy_technology_set_power(connman_proxy_handler_t *connman_proxy_handler, char *obj_path, gboolean powered)
{
	GSList *path_node = NULL;
	connman_proxy_technology_info_t *tech_obj = NULL;
	
    connman_return_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL);

    if((path_node = g_slist_find_custom(connman_proxy_handler->technologies, obj_path, (GCompareFunc)s_connman_find_technology_by_path)))
    {
        tech_obj = path_node->data;
        CONNMAN_LOG_DEBUG("Found Technology Node %p with Object path %s and type %s\n", tech_obj, tech_obj->obj_path, tech_obj->type);
        net_connman_technology_call_set_property(tech_obj->tech_proxy, CONNMAN_PROP_POWERED_STR, g_variant_new("v", g_variant_new_boolean (powered)), NULL, (GAsyncReadyCallback) s_connman_proxy_tech_powered_cb, tech_obj->obj_path);
    }
    else
    {
        CONNMAN_LOG_ERROR("Invalid Technology Object To Configure Power : %s\n", obj_path);
    }
}

/* TODO Tethering releated interfaces not implemented yet*/

/**** Global ****/
