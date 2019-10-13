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

#define CONNMAN_MGR_REQUEST_TIMEOUT (30 * 1000) /* In MiliSeconds*/

static GHashTable *s_pending_req_table = NULL; /* Store input request */
static GMutex s_req_table_mutex;

/* Private struct for storing pending(user input) requests */
typedef struct
{
    connman_mgr_request_input_type_t input_type;
    connman_proxy_on_input_req_cb_t cb;
    NetConnmanAgent *object;
    GDBusMethodInvocation *invocation;
    guint timeout_id;
}connman_mgr_agent_pending_req_pvt_t;

/**** Static ****/
static gpointer s_connman_mgr_request_user_input(gpointer user_data);

static void
s_connman_mgr_parse_request_input(GVariant *properties, connman_mgr_request_input_type_t *input_type)
{
    gchar *key = NULL;
    GVariant *value = NULL;
    GVariantIter iter;

    connman_return_if_invalid_arg(NULL == properties || NULL == input_type);

    *input_type = CONNMAN_MGR_INPUT_TYPE_ENDDEF;

    g_variant_iter_init (&iter, properties);
    while (g_variant_iter_next (&iter, "{sv}", &key, &value))
    {
        if(0 == strcmp(key, "Passphrase"))
        {
            *input_type = CONNMAN_MGR_INPUT_TYPE_PASSPHRASE;
            g_variant_unref (value);
            g_free (key);
            break;
        }
        else
        {
            CONNMAN_LOG_DEBUG("Type %s not supported yet\n", key);
        }
        /*must free data for ourselves*/
        g_variant_unref (value);
        g_free (key);
    }
}

static void
s_clear_pending_requests(gpointer value_data)
{
    CONNMAN_LOG_DEBUG("Cleanup Pending request\n");
    connman_mgr_agent_pending_req_pvt_t *agent_req = (connman_mgr_agent_pending_req_pvt_t *)value_data;

    /* In case if it was a active pending request*/
    if(agent_req->timeout_id)
    {
        g_source_remove(agent_req->timeout_id);
        agent_req->timeout_id = 0;
        g_dbus_method_invocation_return_dbus_error(agent_req->invocation, "net.connman.Agent.Error.Canceled", "User Canceled Request");
    }
    free(agent_req);

    return;
}

static gboolean
s_connman_on_agent_request_timeout (gpointer user_data)
{
    connman_mgr_agent_pending_req_pvt_t *agent_req = NULL;
    connman_mgr_request_input_type_t input_type = GPOINTER_TO_INT(user_data);

    CONNMAN_LOG_WARNING("!!!!!!!!!! Request Input TimedOut !!!!!!!!!! For Request Type %d\n", input_type);

    g_mutex_lock(&s_req_table_mutex);
    agent_req = g_hash_table_lookup(s_pending_req_table, user_data);
    if(agent_req)
    {
        agent_req->timeout_id = 0;
        /* Client did not respond to input request */
        g_dbus_method_invocation_return_dbus_error(agent_req->invocation, "net.connman.Agent.Error.Canceled", "User Did Not Respond");
        g_hash_table_remove(s_pending_req_table, user_data);
    }
    else
    {
        CONNMAN_LOG_WARNING("!!!!!!!!!! Request Has Been Handled or Invalid !!!!!!!!!! for type %d \n", input_type);
    }
    g_mutex_unlock(&s_req_table_mutex);

    return FALSE;
}

static gpointer
s_connman_mgr_request_user_input(gpointer user_data)
{
    connman_mgr_agent_pending_req_pvt_t *agent_req = (connman_mgr_agent_pending_req_pvt_t *)user_data;
    agent_req->cb(agent_req->input_type);
    g_thread_unref (g_thread_self ()); /* Self detach to avoid using join*/
    return NULL;
}

static gboolean
s_connman_mgr_on_handle_request_input_cb (NetConnmanAgent *object, GDBusMethodInvocation *invocation, const gchar *service_obj_path, GVariant *fields, gpointer user_data)
{
    gboolean ret = FALSE;
    connman_mgr_request_input_type_t input_type = CONNMAN_MGR_INPUT_TYPE_ENDDEF;
    connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *)user_data;

    connman_return_val_if_invalid_arg(connman_proxy_handler == NULL, FALSE);

    connman_proxy_util_print_g_variant(connman_proxy_handler->agent_path, fields);
    s_connman_mgr_parse_request_input(fields, &input_type);

    /* Input Request Callback */
    if(connman_proxy_handler->cb && connman_proxy_handler->cb->on_input_req)
    {
        connman_mgr_agent_pending_req_pvt_t *agent_req = NULL;

        g_mutex_lock(&s_req_table_mutex);
        if( NULL == (agent_req = (connman_mgr_agent_pending_req_pvt_t*)malloc(sizeof(connman_mgr_agent_pending_req_pvt_t))))
        {
            CONNMAN_LOG_ERROR("xxxxxxxxxx Memory Allocation Failed xxxxxxxxxx\n");
            g_mutex_unlock(&s_req_table_mutex);
            goto safe_exit;
        }
        agent_req->cb = connman_proxy_handler->cb->on_input_req;
        agent_req->input_type = input_type;
        agent_req->object = object;
        agent_req->invocation = invocation;
        agent_req->timeout_id = g_timeout_add(CONNMAN_MGR_REQUEST_TIMEOUT, s_connman_on_agent_request_timeout, GINT_TO_POINTER(input_type));
        g_hash_table_replace(s_pending_req_table, GINT_TO_POINTER(input_type), agent_req);
        g_mutex_unlock(&s_req_table_mutex);

        /* No need to store and join the return GThread id, It will be dettached using g_thread_unref() before returning from thread*/
        g_thread_new("Input Request Thread", &s_connman_mgr_request_user_input, (gpointer)(agent_req));
    }
    else
    {
        CONNMAN_LOG_WARNING("!!!!!!!!!! Request Input not Handled !!!!!!!!!!\n");
        g_dbus_method_invocation_return_dbus_error(invocation, "net.connman.Agent.Error.Canceled", "This Input Request Type is Not impleted yet");
    }
    ret = TRUE;

safe_exit:
    return ret;
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
    if(0 == strcmp(error, "invalid-key"))
        connman_proxy_util_notify_error_cb(connman_proxy_handler, CONNMAN_PROXY_INVALID_KEY_ERROR);
    else
        connman_proxy_util_notify_error_cb(connman_proxy_handler, CONNMAN_PROXY_UNKNOWN_ERROR);
    net_connman_agent_complete_report_error(object, invocation);
    return TRUE;
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
    CONNMAN_PROXY_UNUSED(user_data);
    net_connman_agent_complete_cancel(object, invocation);
    return TRUE;
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

    s_pending_req_table = g_hash_table_new_full(NULL, NULL, NULL, s_clear_pending_requests);
    if(NULL == s_pending_req_table)
    {
        CONNMAN_LOG_ERROR("xxxxxxxxxx Failed to create Request Table xxxxxxxxxx\n");
        goto safe_exit;
    }
    g_mutex_init(&s_req_table_mutex);

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
    if(s_pending_req_table)
    {
        g_hash_table_destroy(s_pending_req_table);
        s_pending_req_table = NULL;
    }
    g_mutex_clear(&s_req_table_mutex);

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

CP_EXPORT gboolean
connman_mgr_set_user_input(connman_mgr_request_input_type_t input_type, GVariant *response)
{
    gboolean ret = FALSE;
    connman_return_val_if_invalid_arg(NULL == response, ret);

    CONNMAN_LOG_DEBUG("Set User Input Request\n");
    g_mutex_lock(&s_req_table_mutex);
    connman_mgr_agent_pending_req_pvt_t *agent_req = g_hash_table_lookup(s_pending_req_table, GINT_TO_POINTER(input_type));
    if(agent_req)
    {
        if(agent_req->timeout_id)
        {
            g_source_remove(agent_req->timeout_id);
            agent_req->timeout_id = 0;
        }
        switch(input_type)
        {
            case CONNMAN_MGR_INPUT_TYPE_PASSPHRASE:
            {
                net_connman_agent_complete_request_input( agent_req->object, agent_req->invocation, response );
                ret = TRUE;
                break;
            }
            default:
            {
                CONNMAN_LOG_WARNING("!!!!!!!!!! Request input not Supported !!!!!!!!!! for type %d yet\n", input_type);
                g_dbus_method_invocation_return_error (agent_req->invocation, G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD, "Method INPUT REQUEST for type %d is not implemented", input_type);
                break;
            }
        }/*switch*/
        g_hash_table_remove(s_pending_req_table, GINT_TO_POINTER(input_type));
    }
    else
    {
        CONNMAN_LOG_WARNING("!!!!!!!!!! Request Has Expired or Invalid !!!!!!!!!! for type %d \n", input_type);
    }

    g_mutex_unlock(&s_req_table_mutex);
    return ret;
}

CP_EXPORT void
connman_mgr_cancel_user_input(connman_mgr_request_input_type_t input_type)
{
    CONNMAN_LOG_DEBUG("Cancel User Input Request\n");
    g_mutex_lock(&s_req_table_mutex);
    connman_mgr_agent_pending_req_pvt_t *agent_req = g_hash_table_lookup(s_pending_req_table, GINT_TO_POINTER(input_type));
    if(agent_req)
    {
        if(agent_req->timeout_id)
        {
            g_source_remove(agent_req->timeout_id);
            agent_req->timeout_id = 0;
        }
        g_dbus_method_invocation_return_dbus_error(agent_req->invocation, "net.connman.Agent.Error.Canceled", "User Canceled Request");
        g_hash_table_remove(s_pending_req_table, GINT_TO_POINTER(input_type));
    }
    else
    {
        CONNMAN_LOG_WARNING("!!!!!!!!!! Request Has Expired or Invalid !!!!!!!!!! for type %d \n", input_type);
    }
    g_mutex_unlock(&s_req_table_mutex);
}
