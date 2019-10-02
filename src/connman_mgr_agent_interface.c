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
 *  File             : connman_mgr_agent_interface.c
 *  Description      : The manager Code for the connmand. i.e connmand will call these methods which we have to define
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

/**** Static ****/
static gboolean
s_connman_mgr_on_handle_request_input_cb (NetConnmanAgent *object, GDBusMethodInvocation *invocation, const gchar *service_obj_path, GVariant *fields, gpointer user_data)
{
    GVariantBuilder * input_builder = NULL;
    gchar value[100];

    connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *)user_data;

    connman_return_val_if_invalid_arg(connman_proxy_handler == NULL, FALSE);

    connman_proxy_util_print_g_variant(connman_proxy_handler->agent_path, fields);
    CONNMAN_LOG_USER("%s: Enter Password : ", service_obj_path ? service_obj_path :" Unknown Service");
    scanf("%s", value);

    input_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

    GVariant *_value = g_variant_new("s", value);
    g_variant_builder_add (input_builder, "{sv}", "Passphrase", _value);
    GVariant *res = g_variant_new("a{sv}", input_builder);

    net_connman_agent_complete_request_input( object, invocation, res );
    g_variant_builder_unref (input_builder);

    return TRUE;
}

static gboolean
s_connman_mgr_on_handle_request_browser_cb (NetConnmanAgent *object, GDBusMethodInvocation *invocation, const gchar *service_obj_path, gchar *url, gpointer user_data)
{
    CONNMAN_LOG_WARNING("!!!!!!!!!! Request Browser Not Implemented !!!!!!!!!! : Service %s , Url : %s\n", service_obj_path ? service_obj_path :" Unknown Service", url);
    CONNMAN_PROXY_UNUSED(object);
    CONNMAN_PROXY_UNUSED(invocation);
    CONNMAN_PROXY_UNUSED(user_data);
    return FALSE;
}

static gboolean
s_connman_mgr_on_handle_report_error_cb (NetConnmanAgent *object, GDBusMethodInvocation *invocation, const gchar *service_obj_path, gchar *error, gpointer user_data)
{
    connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *)user_data;
    CONNMAN_LOG_WARNING("!!!!!!!!!! Report Error Partially Implemented !!!!!!!!!! : Service %s , Error : %s\n", service_obj_path ? service_obj_path :" Unknown Service", error);
    CONNMAN_PROXY_UNUSED(object);
    CONNMAN_PROXY_UNUSED(invocation);
    CONNMAN_PROXY_UNUSED(user_data);
    if(0 == strcmp(error, "invalid-key"))
        connman_proxy_util_notify_error_cb(connman_proxy_handler, CONNMAN_PROXY_INVALID_KEY_ERROR);
    else
        connman_proxy_util_notify_error_cb(connman_proxy_handler, CONNMAN_PROXY_UNKNOWN_ERROR);
    return FALSE;
}

static gboolean
s_connman_mgr_on_handle_report_peer_error_cb (NetConnmanAgent *object, GDBusMethodInvocation *invocation, const gchar *peer_path, gchar *error, gpointer user_data)
{
    CONNMAN_LOG_WARNING("!!!!!!!!!! Report Peer Error Not Implemented !!!!!!!!!! : Peer %s , Error : %s\n", peer_path ? peer_path :" Unknown Peer", error);
    CONNMAN_PROXY_UNUSED(object);
    CONNMAN_PROXY_UNUSED(invocation);
    CONNMAN_PROXY_UNUSED(user_data);
    return FALSE;
}

static gboolean
s_connman_mgr_on_handle_cancel_cb (NetConnmanAgent *object, GDBusMethodInvocation *invocation, gpointer user_data)
{
    CONNMAN_LOG_WARNING("!!!!!!!!!! Agent request failed before a reply was returned !!!!!!!!!!\n");
    CONNMAN_PROXY_UNUSED(object);
    CONNMAN_PROXY_UNUSED(invocation);
    CONNMAN_PROXY_UNUSED(user_data);
    return FALSE;
}

/* Service daemon has unregistered agent*/
static gboolean
s_connman_mgr_on_handle_release_cb (NetConnmanAgent *object, GDBusMethodInvocation *invocation, gpointer user_data)
{
    connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *)user_data;
    connman_proxy_handler->agent_registered = FALSE;
    net_connman_agent_complete_release( object, invocation);
    return TRUE;
}

/**** Hidden ****/

gboolean 
connman_mgr_agent_init(connman_proxy_handler_t *connman_proxy_handler)
{
    GError *err = NULL;
    gboolean ret = FALSE;

    connman_return_val_if_invalid_arg(connman_proxy_handler == NULL, FALSE);
 
    connman_proxy_handler->agent_path = g_strdup_printf("/net/connman/connmanproxy_%d", getpid());
    if(connman_proxy_handler->agent_path == NULL)
    {
        CONNMAN_LOG_ERROR("xxxxxxxxxx Invalid Agent Path xxxxxxxxxx\n");
        goto safe_exit;
    }

    connman_proxy_handler->agent_mgr_server = g_dbus_object_manager_server_new (connman_proxy_handler->agent_path);
    if(connman_proxy_handler->agent_mgr_server == NULL)
    {
        CONNMAN_LOG_ERROR("xxxxxxxxxx Could Not Get Connman Agent Manager Server xxxxxxxxxx\n");
        goto safe_exit;
    }

    connman_proxy_handler->agent_mgr = net_connman_agent_skeleton_new ();
    if(connman_proxy_handler->agent_mgr == NULL)
    {
        CONNMAN_LOG_ERROR("xxxxxxxxxx Could Not Get Connman Agent manager xxxxxxxxxx\n");
        goto safe_exit;
    }

    if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (connman_proxy_handler->agent_mgr),
                                            connman_proxy_handler->connection,
                                            connman_proxy_handler->agent_path,
                                            &err))
    {   
        CONNMAN_LOG_ERROR("xxxxxxxxxx %s xxxxxxxxxx\n", err ? err->message: "Agent Unknown Error");
        if(err)
            g_error_free (err);
        goto safe_exit;
    }   
    g_dbus_object_manager_server_set_connection (connman_proxy_handler->agent_mgr_server, connman_proxy_handler->connection);

    connman_proxy_handler->request_input_sid = g_signal_connect (connman_proxy_handler->agent_mgr, "handle-request-input", G_CALLBACK (s_connman_mgr_on_handle_request_input_cb), connman_proxy_handler);
    connman_proxy_handler->request_browser_sid = g_signal_connect (connman_proxy_handler->agent_mgr, "handle-request-browser", G_CALLBACK (s_connman_mgr_on_handle_request_browser_cb), connman_proxy_handler);
    connman_proxy_handler->report_error_sid = g_signal_connect (connman_proxy_handler->agent_mgr, "handle-report-error", G_CALLBACK (s_connman_mgr_on_handle_report_error_cb), connman_proxy_handler);
    connman_proxy_handler->report_peer_error_sid = g_signal_connect (connman_proxy_handler->agent_mgr, "handle-report-peer-error", G_CALLBACK (s_connman_mgr_on_handle_report_peer_error_cb), connman_proxy_handler);
    connman_proxy_handler->cancel_sid = g_signal_connect (connman_proxy_handler->agent_mgr, "handle-cancel", G_CALLBACK (s_connman_mgr_on_handle_cancel_cb), connman_proxy_handler);
    connman_proxy_handler->release_sid = g_signal_connect (connman_proxy_handler->agent_mgr, "handle-release", G_CALLBACK (s_connman_mgr_on_handle_release_cb), connman_proxy_handler);

    ret = TRUE;

safe_exit:
    if(ret == FALSE)
    {
        /* Cleanup in case of error*/
        connman_mgr_agent_deinit(connman_proxy_handler);
    }
    return ret;
}

void 
connman_mgr_agent_deinit(connman_proxy_handler_t *connman_proxy_handler)
{
    /*Unregister WIFI agent*/
    connman_proxy_mgr_unregister_agent(connman_proxy_handler);
    if(connman_proxy_handler->agent_path)
    {
        g_free(connman_proxy_handler->agent_path);
        connman_proxy_handler->agent_path = NULL;
    }

    if(connman_proxy_handler->agent_mgr_server)
        g_object_unref(connman_proxy_handler->agent_mgr_server);

    /* Remove signal handlers*/
    if(connman_proxy_handler->request_input_sid)
        g_signal_handler_disconnect(connman_proxy_handler->agent_mgr, connman_proxy_handler->request_input_sid);
    if(connman_proxy_handler->request_browser_sid)
        g_signal_handler_disconnect(connman_proxy_handler->agent_mgr, connman_proxy_handler->request_browser_sid);
    if(connman_proxy_handler->report_error_sid)
        g_signal_handler_disconnect(connman_proxy_handler->agent_mgr, connman_proxy_handler->report_error_sid);
    if(connman_proxy_handler->report_peer_error_sid)
        g_signal_handler_disconnect(connman_proxy_handler->agent_mgr, connman_proxy_handler->report_peer_error_sid);
    if(connman_proxy_handler->cancel_sid)
        g_signal_handler_disconnect(connman_proxy_handler->agent_mgr, connman_proxy_handler->cancel_sid);
    if(connman_proxy_handler->release_sid)
        g_signal_handler_disconnect(connman_proxy_handler->agent_mgr, connman_proxy_handler->release_sid);
}

/**** Global ****/
