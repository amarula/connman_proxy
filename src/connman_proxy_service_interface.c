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
 *  File             : connman_proxy_service_interface.c
 *  Description      : Proxy Interface sofr connman service object
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

#define CONNMAN_PROXY_SERVICE_PARSE_PROPERTY(service_obj, key, value) \
        if(strcmp(key, CONNMAN_PROP_TYPE_STR) == 0) \
            CONNMAN_VAR_GET_STR_COPY(value, &service_obj->type[0]) \
        else if(strcmp(key, CONNMAN_PROP_SECURITY_STR) == 0) \
        {\
            CONNMAN_PROXY_FREE_STR_GLIST(service_obj->security);\
            CONNMAN_VAR_GET_STR_ARRAY(value, service_obj->security) \
        }\
        else if(strcmp(key, CONNMAN_PROP_STATE_STR) == 0) \
            CONNMAN_VAR_GET_STR_COPY(value, &service_obj->state[0]) \
        else if(strcmp(key, CONNMAN_PROP_FAVORITE_STR) == 0) \
            CONNMAN_VAR_GET_BOOL(value, service_obj->favorite) \
        else if(strcmp(key, CONNMAN_PROP_IMMUTABLE_STR) == 0) \
            CONNMAN_VAR_GET_BOOL(value, service_obj->immutable) \
        else if(strcmp(key, CONNMAN_PROP_AUTOCONNECT_STR) == 0) \
            CONNMAN_VAR_GET_BOOL(value, service_obj->autoconnect) \
        else if(strcmp(key, CONNMAN_PROP_MDNS_STR) == 0) \
            CONNMAN_VAR_GET_BOOL(value, service_obj->mdns) \
        else if(strcmp(key, CONNMAN_PROP_NAME_STR) == 0) \
            CONNMAN_VAR_GET_STR_DUP(value, service_obj->name) \
        else if(strcmp(key, CONNMAN_PROP_STRENGTH_STR) == 0)\
            CONNMAN_VAR_GET_BYTE(value, service_obj->signal_strength)\
        else if(strcmp(key, CONNMAN_PROP_IPV4_STR) == 0) \
        {\
            memset(&service_obj->ipv4, 0, sizeof(connman_proxy_ipv4_info_t)); /* clear existing data*/\
            s_connman_proxy_parse_service_properties(service_obj, key, value); \
        }\
        else if(strcmp(key, CONNMAN_PROP_IPV6_STR) == 0) \
        {\
            memset(&service_obj->ipv6, 0, sizeof(connman_proxy_ipv6_info_t)); /* clear existing data*/\
            s_connman_proxy_parse_service_properties(service_obj, key, value); \
        }\
        else if(strcmp(key, CONNMAN_PROP_ETHERNET_STR) == 0) \
        {\
            memset(&service_obj->eth, 0, sizeof(connman_proxy_eth_info_t)); /* clear existing data*/\
            s_connman_proxy_parse_service_properties(service_obj, key, value); \
        }\
        else if(strcmp(key, CONNMAN_PROP_PROXY_STR) == 0) \
        {\
            CONNMAN_PROXY_FREE_STR_GLIST(service_obj->proxy.servers); /* Free and clear existing data*/\
            CONNMAN_PROXY_FREE_STR_GLIST(service_obj->proxy.exclude);\
            CONNMAN_PROXY_SAFE_FREE(service_obj->proxy.url);\
            memset(&service_obj->proxy, 0, sizeof(connman_proxy_proxy_info_t));\
            s_connman_proxy_parse_service_properties(service_obj, key, value); \
        }\
        else if(strcmp(key, CONNMAN_PROP_NAMESERV_STR) == 0) \
        {\
            CONNMAN_PROXY_FREE_STR_GLIST(service_obj->nameservers);\
            CONNMAN_VAR_GET_STR_ARRAY(value, service_obj->nameservers) \
        }\
        else if(strcmp(key, CONNMAN_PROP_TIMESERV_STR) == 0) \
        {\
            CONNMAN_PROXY_FREE_STR_GLIST(service_obj->timeservers);\
            CONNMAN_VAR_GET_STR_ARRAY(value, service_obj->timeservers) \
        }\
        else if(strcmp(key, CONNMAN_PROP_DOMAINS_STR) == 0) \
        {\
            CONNMAN_PROXY_FREE_STR_GLIST(service_obj->domains);\
            CONNMAN_VAR_GET_STR_ARRAY(value, service_obj->domains) \
        }\
        else \
        { \
            CONNMAN_LOG_WARNING("Unknown Property : %s Type %s\n", key, g_variant_get_type_string (value)); \
        }

#define CONNMAN_BUILD_GVAR_STRING_ARRAY(builder, value_list) \
        {\
            int8_t i = 0; \
            builder = g_variant_builder_new (G_VARIANT_TYPE ("as")); \
            if(builder == NULL)\
            {\
                CONNMAN_LOG_ERROR("Could not build String Array Variant Builder\n"); \
                goto safe_exit; \
            }\
            while (value_list[i]) \
            { \
                CONNMAN_LOG_DEBUG("%d : Append String %s\n", i, value_list[i]); \
                g_variant_builder_add (builder, "s", value_list[i]); \
                i++; \
            } \
        }

/**** Static ****/

static void
s_connman_proxy_parse_service_properties(connman_proxy_service_info_t *service_obj, gchar *prop_name, GVariant *properties)
{
    gsize str_len = 0; /* str_len and str_val To be used in PARSE macro, same name will be used in macro*/
    const gchar *str_val = NULL;
    GVariantIter iter;
    GVariant *res = NULL;
    gchar *key = NULL;

    connman_return_if_invalid_arg(service_obj == NULL || prop_name == NULL || properties == NULL);

    g_variant_iter_init (&iter, properties);
    while (g_variant_iter_next (&iter, "{sv}", &key, &res))
    {
        if(strncmp(CONNMAN_PROP_ETHERNET_STR, prop_name, strlen(prop_name)) == 0) /*Ethernet*/
        {
            connman_proxy_eth_info_t *eth = &service_obj->eth;
            if(strcmp(key, CONNMAN_PROP_METHOD_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &eth->method[0])
            else if(strcmp(key, CONNMAN_PROP_INTERFACE_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &eth->interface[0])
            else if(strcmp(key, CONNMAN_PROP_ADDRESS_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &eth->address[0])
            else if(strcmp(key, "MTU") == 0)
                CONNMAN_VAR_GET_UINT16(res, eth->mtu)
        }
        else if(strncmp(CONNMAN_PROP_IPV4_STR, prop_name, strlen(prop_name)) == 0) /*IPV4*/
		{
            connman_proxy_ipv4_info_t *ipv4 = &service_obj->ipv4;
            if(strcmp(key, CONNMAN_PROP_METHOD_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &ipv4->method[0])
            else if(strcmp(key, CONNMAN_PROP_ADDRESS_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &ipv4->address[0])
            else if(strcmp(key, CONNMAN_PROP_NETMASK_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res,  &ipv4->netmask[0])
            else if(strcmp(key, CONNMAN_PROP_GATEWAY_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &ipv4->gateway[0])
		}
        else if(strncmp(CONNMAN_PROP_IPV6_STR, prop_name, strlen(prop_name)) == 0) /*IPV6*/
        {
            connman_proxy_ipv6_info_t *ipv6 = &service_obj->ipv6;
            if(strcmp(key, CONNMAN_PROP_METHOD_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &ipv6->method[0])
            else if(strcmp(key, CONNMAN_PROP_ADDRESS_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &ipv6->address[0])
            else if(strcmp(key, CONNMAN_PROP_PROXYLENTGH_STR) == 0)
                CONNMAN_VAR_GET_BYTE(res, ipv6->prefix_length)
            else if(strcmp(key, CONNMAN_PROP_GATEWAY_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &ipv6->gateway[0])
            else if(strcmp(key, CONNMAN_PROP_PRIVACY_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &ipv6->privacy[0])
        }
        else if(strncmp(CONNMAN_PROP_PROXY_STR, prop_name, strlen(prop_name)) == 0) /*Ethernet Proxy*/
        {
            connman_proxy_proxy_info_t *proxy = &service_obj->proxy;
            if(strcmp(key, CONNMAN_PROP_METHOD_STR) == 0)
                CONNMAN_VAR_GET_STR_COPY(res, &proxy->method[0])
            else if(strcmp(key, CONNMAN_PROP_URL_STR) == 0)
                CONNMAN_VAR_GET_STR_DUP(res, proxy->url)
            else if(strcmp(key, CONNMAN_PROP_SERVERS_STR) == 0) /* When Method is manual*/
            {
                CONNMAN_PROXY_FREE_STR_GLIST(proxy->servers);
                CONNMAN_VAR_GET_STR_ARRAY(res, proxy->servers)
            }
            else if(strcmp(key, CONNMAN_PROP_EXCLUDES_STR) == 0) /* When method is manual*/
            {
                CONNMAN_PROXY_FREE_STR_GLIST(proxy->exclude);
                CONNMAN_VAR_GET_STR_ARRAY(res, proxy->exclude)
            }
        }
        else
        {
            CONNMAN_LOG_WARNING("[%s] Type %s Unimplemented\n", prop_name, g_variant_get_type_string (res));
        }
        g_variant_unref (res);
        g_free (key);
	}/*While iter {sv}*/
}

static void
s_connman_proxy_service_connect_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    connman_proxy_service_info_t *service_obj = (connman_proxy_service_info_t *)user_data;

    ret = net_connman_service_call_connect_finish (NET_CONNMAN_SERVICE(proxy), res, &error);
    if(ret == TRUE)
    {
        CONNMAN_LOG_INFO("Connected to Service %s\n", service_obj ? service_obj->service_name : "Unknown" );
    }
    else
    {
        CONNMAN_LOG_ERROR("Could Not Connect to Service %s : %s\n", service_obj ? service_obj->service_name : "Unknown", error->message);
        g_error_free (error);
    }
    return;
}

static void
s_connman_proxy_service_disconnect_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    connman_proxy_service_info_t *service_obj = (connman_proxy_service_info_t *)user_data;

    ret = net_connman_service_call_disconnect_finish (NET_CONNMAN_SERVICE(proxy), res, &error);
    if(ret == TRUE)
    {
        CONNMAN_LOG_INFO("Disconnected Service %s\n", service_obj ? service_obj->service_name : "Unknown" );
    }
    else
    {
        CONNMAN_LOG_ERROR("Could Not Disconnect Service %s : %s\n", service_obj ? service_obj->service_name : "Unknown", error->message);
        g_error_free (error);
    }
    return;
}

static void
s_connman_proxy_service_remove_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    connman_proxy_service_info_t *service_obj = (connman_proxy_service_info_t *)user_data;

    ret = net_connman_service_call_remove_finish (NET_CONNMAN_SERVICE(proxy), res, &error);
    if(ret == TRUE)
    {
        CONNMAN_LOG_INFO("Forgot Service %s\n", service_obj ? service_obj->service_name : "Unknown" );
    }
    else
    {
        CONNMAN_LOG_ERROR("Could Not Forget Service %s : %s\n", service_obj ? service_obj->service_name : "Unknown", error->message);
        g_error_free (error);
    }
    return;
}

static void
s_connman_proxy_service_autoconnect_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    connman_proxy_service_info_t *service_obj = (connman_proxy_service_info_t *)user_data;

    ret = net_connman_service_call_set_property_finish (NET_CONNMAN_SERVICE(proxy), res, &error);
    if(ret == TRUE)
    {
        CONNMAN_LOG_INFO("Configured Autoconnect For Service %s\n", service_obj ? service_obj->service_name : "Unknown" );
    }
    else
    {
        CONNMAN_LOG_ERROR("Could Not Configure Autoconnect For Service %s : %s\n", service_obj ? service_obj->service_name : "Unknown", error->message);
        g_error_free (error);
    }
    return;
}

static void
s_connman_proxy_service_mdns_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    connman_proxy_service_info_t *service_obj = (connman_proxy_service_info_t *)user_data;

    ret = net_connman_service_call_set_property_finish (NET_CONNMAN_SERVICE(proxy), res, &error);
    if(ret == TRUE)
    {
        CONNMAN_LOG_INFO("Configured MDNS For Service %s\n", service_obj ? service_obj->service_name : "Unknown" );
    }
    else
    {
        CONNMAN_LOG_ERROR("Could Not Configure MDNS For Service %s : %s\n", service_obj ? service_obj->service_name : "Unknown", error->message);
        g_error_free (error);
    }
    return;
}

static void
s_connman_proxy_pv4_config_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    connman_proxy_service_info_t *service_obj = (connman_proxy_service_info_t *)user_data;

    ret = net_connman_service_call_set_property_finish (NET_CONNMAN_SERVICE(proxy), res, &error);
    if(ret == TRUE)
    {
        CONNMAN_LOG_INFO("Configured IPV4 For Service %s\n", service_obj ? service_obj->service_name : "Unknown" );
    }
    else
    {
        CONNMAN_LOG_ERROR("Could Not Configure IPV4 For Service %s : %s\n", service_obj ? service_obj->service_name : "Unknown", error->message);
        g_error_free (error);
    }
    return;
}

static void
s_connman_proxy_proxy_config_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    CONNMAN_LOG_WARNING("!!!!!!!!!! Not Implemented !!!!!!!!!!!!!!!!!!!!\n");
    CONNMAN_PROXY_UNUSED(proxy);
    CONNMAN_PROXY_UNUSED(res);
    CONNMAN_PROXY_UNUSED(user_data);
    ret = net_connman_service_call_set_property_finish (NET_CONNMAN_SERVICE(proxy), res, &error);
    CONNMAN_PROXY_UNUSED(ret);
}

static void
s_connman_proxy_nameserver_config_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    connman_proxy_service_info_t *service_obj = (connman_proxy_service_info_t *)user_data;

    ret = net_connman_service_call_set_property_finish (NET_CONNMAN_SERVICE(proxy), res, &error);
    if(ret == TRUE)
    {
        CONNMAN_LOG_INFO("Configured NameServer For Service %s\n", service_obj ? service_obj->service_name : "Unknown" );
    }
    else
    {
        CONNMAN_LOG_ERROR("Could Not Configure NameServer For Service %s : %s\n", service_obj ? service_obj->service_name : "Unknown", error->message);
        g_error_free (error);
    }
    return;
}

static void
s_connman_proxy_timeserver_config_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    CONNMAN_LOG_WARNING("!!!!!!!!!! Not Implemented !!!!!!!!!!!!!!!!!!!!\n");
    CONNMAN_PROXY_UNUSED(proxy);
    CONNMAN_PROXY_UNUSED(res);
    CONNMAN_PROXY_UNUSED(user_data);
    ret = net_connman_service_call_set_property_finish (NET_CONNMAN_SERVICE(proxy), res, &error);
    CONNMAN_PROXY_UNUSED(ret);
}

static void
s_connman_proxy_domain_config_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                gpointer      user_data)
{
    GError *error = NULL;
    gboolean ret  =  FALSE;
    CONNMAN_LOG_WARNING("!!!!!!!!!! Not Implemented !!!!!!!!!!!!!!!!!!!!\n");
    CONNMAN_PROXY_UNUSED(proxy);
    CONNMAN_PROXY_UNUSED(res);
    CONNMAN_PROXY_UNUSED(user_data);
    ret = net_connman_service_call_set_property_finish (NET_CONNMAN_SERVICE(proxy), res, &error);
    CONNMAN_PROXY_UNUSED(ret);
}

static void
s_connman_proxy_srv_entry_free(gpointer data)
{
    connman_proxy_service_info_t *service_obj = data;

    if (service_obj != NULL)
    {
        /* cleanup  members without child*/
        CONNMAN_PROXY_SAFE_FREE(service_obj->service_name);
        CONNMAN_PROXY_SAFE_FREE(service_obj->obj_path);
        CONNMAN_PROXY_SAFE_FREE(service_obj->name);

        CONNMAN_PROXY_FREE_STR_GLIST(service_obj->nameservers);
        CONNMAN_PROXY_FREE_STR_GLIST(service_obj->timeservers);
        CONNMAN_PROXY_FREE_STR_GLIST(service_obj->domains);
        CONNMAN_PROXY_FREE_STR_GLIST(service_obj->security);

        /* cleanup  members with child*/
        CONNMAN_PROXY_FREE_STR_GLIST(service_obj->proxy.servers);
        CONNMAN_PROXY_FREE_STR_GLIST(service_obj->proxy.exclude);

        CONNMAN_PROXY_SAFE_FREE(service_obj->proxy.url);

        g_object_unref(service_obj->srv_proxy);

        /*Clean up main object*/
        free(service_obj);
    }
    return;
}

/**** Hidden ****/
void
connman_proxy_service_init(connman_proxy_handler_t *connman_proxy_handler)
{
    if(connman_proxy_handler->services == NULL)
        connman_proxy_handler->services = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, (GDestroyNotify) s_connman_proxy_srv_entry_free);
    else
    {
        CONNMAN_LOG_WARNING("!!!!!!!!!! Connman Service is already initialized !!!!!!!!!!\n");
    }
    return;
}

void
connman_proxy_service_deinit(connman_proxy_handler_t *connman_proxy_handler)
{
    if(connman_proxy_handler->services == NULL)
    {
        CONNMAN_LOG_WARNING("!!!!!!!!!! Connman Service is not initialized !!!!!!!!!!\n");
    }
    else
    {
        g_hash_table_remove_all(connman_proxy_handler->services);
        g_hash_table_destroy (connman_proxy_handler->services);
        connman_proxy_handler->services = NULL;
    }
    return;
}

void
connman_proxy_service_property_changed_cb(NetConnmanService *object, char *name, GVariant *unboxed_value, gpointer user_data)
{
    gsize str_len = 0; /* str_len and str_val To be used in PARSE macro, same name will be used in macro*/
    const gchar *str_val = NULL;
    connman_proxy_service_info_t *service_obj = (connman_proxy_service_info_t *)user_data;

    connman_return_if_invalid_arg(service_obj == NULL);
    CONNMAN_PROXY_UNUSED(object);

    CONNMAN_LOG_USER("[%s] Property Changed : %s\n", service_obj->service_name, name);
    CONNMAN_PROXY_SERVICE_PARSE_PROPERTY(service_obj, name, unboxed_value)
    connman_proxy_util_print_g_variant(name, unboxed_value);
}

int8_t
connman_proxy_service_add_new(connman_proxy_handler_t *connman_proxy_handler, gchar *obj_path, GVariant *properties)
{
    int8_t ret = -1;
    const char *serv_name = NULL;
    gsize str_len = 0; /* str_len and str_val To be used in PARSE macro, same name will be used in macro*/
    const gchar *str_val = NULL;

    gchar *key = NULL;
    GError *err = NULL;
    GVariant *value = NULL;
    GVariantIter iter;
    connman_proxy_service_info_t *service_obj = NULL;

    connman_return_val_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL, -1);

    serv_name = strrchr(obj_path, '/'); 
    
    service_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(service_obj == NULL) /* New Service */
    {
        CONNMAN_LOG_INFO("+++++++++++ A New Service Has Been Added +++++++++++ Path : %s\n", obj_path);
        if((service_obj = g_new0(connman_proxy_service_info_t, 1)) == NULL)
        {
            CONNMAN_LOG_ERROR("Memory Allocation Failed : %s\n", obj_path);
            goto safe_exit;
        }
    
        service_obj->srv_proxy = net_connman_service_proxy_new_sync(connman_proxy_handler->connection, G_DBUS_PROXY_FLAGS_NONE, CONNMAN_SERVICE, obj_path, NULL, &err);
        if(service_obj->srv_proxy == NULL)
        {
            CONNMAN_LOG_ERROR("Could Not Connect to Service Proxy %s : %s\n", serv_name ? serv_name : obj_path, err ? err->message : "Unknown Reason");
            if(err)
                g_error_free (err);
            g_free(service_obj);
            goto safe_exit;
        }
        service_obj->obj_path = g_strdup(obj_path);
        service_obj->service_name = (serv_name) ? g_strdup(serv_name + 1) : g_strdup(obj_path);
        g_hash_table_replace(connman_proxy_handler->services, service_obj->obj_path, service_obj);
        CONNMAN_UTIL_PRINT_G_VARIENT(obj_path, properties);
    }
    else
    {
        CONNMAN_LOG_TRACE("Service %s updated\n", service_obj->obj_path);
    }

    /* Parse property and update */
    g_variant_iter_init (&iter, properties);
    while (g_variant_iter_next (&iter, "{sv}", &key, &value))
    {   
        CONNMAN_PROXY_SERVICE_PARSE_PROPERTY(service_obj, key, value);
        /*must free data for ourselves*/
        g_variant_unref (value);
        g_free (key);
    }

    ret = 0;

safe_exit:
    return ret;
}

void
connman_proxy_service_remove_from_table(connman_proxy_handler_t *connman_proxy_handler, char *obj_path)
{
    connman_proxy_service_info_t *service_obj = NULL;

    connman_return_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL);
    
    service_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(service_obj == NULL)
    {
        CONNMAN_LOG_ERROR("Remove Error : Could not find service path : %s\n", obj_path);
        goto safe_exit;
    }
    
    g_hash_table_remove (connman_proxy_handler->services, (gconstpointer) obj_path);

safe_exit:
    return;
}

/**** Global ****/
void 
connman_proxy_service_connect(connman_proxy_handler_t *connman_proxy_handler, char *obj_path)
{
    connman_proxy_service_info_t *serv_obj = NULL;

    connman_return_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL);

    serv_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(serv_obj == NULL)
    {
        CONNMAN_LOG_ERROR("Connect Error : Could not find service %s\n", obj_path);
        goto safe_exit;
    }

    net_connman_service_call_connect(serv_obj->srv_proxy, NULL, (GAsyncReadyCallback)s_connman_proxy_service_connect_cb, serv_obj);

safe_exit:
    return;
}

void 
connman_proxy_service_disconnect(connman_proxy_handler_t *connman_proxy_handler, char *obj_path)
{
    connman_proxy_service_info_t *serv_obj = NULL;

    connman_return_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL);

    serv_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(serv_obj == NULL)
    {
        CONNMAN_LOG_ERROR("DisConnect Error : Could not find service %s\n", obj_path);
        goto safe_exit;
    }

    net_connman_service_call_disconnect(serv_obj->srv_proxy, NULL, (GAsyncReadyCallback)s_connman_proxy_service_disconnect_cb, serv_obj);

safe_exit:
    return;
}

void 
connman_proxy_service_remove(connman_proxy_handler_t *connman_proxy_handler, char *obj_path)
{
    connman_proxy_service_info_t *serv_obj = NULL;

    connman_return_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL);

    serv_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(serv_obj == NULL)
    {
        CONNMAN_LOG_ERROR("Remove Error : Could not find service %s\n", obj_path);
        goto safe_exit;
    }

    net_connman_service_call_remove(serv_obj->srv_proxy, NULL, (GAsyncReadyCallback)s_connman_proxy_service_remove_cb, serv_obj);

safe_exit:
    return;
}

/* TODO Move Before */
/* TODO Move After */
/* TODO Clear Property */

/* All set property related */
void
connman_proxy_service_set_autoconnect(connman_proxy_handler_t *connman_proxy_handler, char *obj_path, gboolean autoconnect)
{
    connman_proxy_service_info_t *serv_obj = NULL;

    connman_return_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL);

    serv_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(serv_obj == NULL)
    {
        CONNMAN_LOG_ERROR("Connect Error : Could not find service %s\n", obj_path);
        return;
    }
    net_connman_service_call_set_property(serv_obj->srv_proxy, CONNMAN_PROP_AUTOCONNECT_STR, g_variant_new("v", g_variant_new_boolean (autoconnect)), NULL, (GAsyncReadyCallback)s_connman_proxy_service_autoconnect_cb, serv_obj);
}

int8_t
connman_proxy_service_config_ipv4(connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char *method, char *addr, char *mask, char *gw)
{
    int8_t ret = CONNMAN_PROXY_FAIL;
    GVariantBuilder *ipv4_builder = NULL;
    GVariant *dict = NULL;
    connman_proxy_service_info_t *serv_obj = NULL;

    connman_return_val_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL || method == NULL, CONNMAN_PROXY_FAIL);

    serv_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(serv_obj == NULL)
    {
        CONNMAN_LOG_ERROR("Connect Error : Could not find service %s\n", obj_path);
        return CONNMAN_PROXY_FAIL;
    }
    ipv4_builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));
    if(ipv4_builder)
    {
        g_variant_builder_add (ipv4_builder, "{sv}", CONNMAN_PROP_METHOD_STR, g_variant_new_string (method));
        if(strncmp(method, "manual", strlen(method)) == 0)
        {
            connman_return_val_if_invalid_arg(addr == NULL, CONNMAN_PROXY_FAIL); /* When set to manual atleast pass the address*/
            g_variant_builder_add (ipv4_builder, "{sv}", CONNMAN_PROP_ADDRESS_STR, g_variant_new_string (addr));

            if(mask)
                g_variant_builder_add (ipv4_builder, "{sv}", CONNMAN_PROP_NETMASK_STR, g_variant_new_string (mask));
            if(gw)
                g_variant_builder_add (ipv4_builder, "{sv}", CONNMAN_PROP_GATEWAY_STR, g_variant_new_string (gw));
        }
        dict = g_variant_builder_end (ipv4_builder);
        net_connman_service_call_set_property(serv_obj->srv_proxy, CONNMAN_PROP_IPV4_STR".Configuration", g_variant_new("v", dict), NULL, (GAsyncReadyCallback)s_connman_proxy_pv4_config_cb, serv_obj);
        g_variant_builder_unref (ipv4_builder);
        ret = CONNMAN_PROXY_SUCCESS;
    }
    else
    {
        CONNMAN_LOG_ERROR("IPV4 Config Error : Couldnt Build  Gvariant for %s\n", obj_path);
    }
    return ret;
}

int8_t
connman_proxy_service_config_nameserver(connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char **dns_list)
{
    int8_t ret = CONNMAN_PROXY_FAIL;
    GVariantBuilder *dns_builder = NULL;
    GVariant *dict = NULL;
    connman_proxy_service_info_t *serv_obj = NULL;

    connman_return_val_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL || dns_list == NULL, CONNMAN_PROXY_FAIL);
    serv_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(serv_obj == NULL)
    {
        CONNMAN_LOG_ERROR("Connect Error : Could not find service %s\n", obj_path);
        return CONNMAN_PROXY_FAIL;
    }
    CONNMAN_BUILD_GVAR_STRING_ARRAY(dns_builder, dns_list);
    dict = g_variant_builder_end(dns_builder);
    net_connman_service_call_set_property(serv_obj->srv_proxy, CONNMAN_PROP_NAMESERV_STR".Configuration", g_variant_new("v", dict), NULL, (GAsyncReadyCallback)s_connman_proxy_nameserver_config_cb, serv_obj);
    g_variant_builder_unref (dns_builder);
    ret = CONNMAN_PROXY_SUCCESS;
safe_exit:
    return ret;
}

int8_t
connman_proxy_service_config_timeserver(connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char **ntps_list)
{
    int8_t ret = CONNMAN_PROXY_FAIL;
    GVariantBuilder *ntps_builder = NULL;
    GVariant *dict = NULL;
    connman_proxy_service_info_t *serv_obj = NULL;

    connman_return_val_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL || ntps_list == NULL, CONNMAN_PROXY_FAIL);
    serv_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(serv_obj == NULL)
    {
        CONNMAN_LOG_ERROR("Connect Error : Could not find service %s\n", obj_path);
        return CONNMAN_PROXY_FAIL;
    }
    CONNMAN_BUILD_GVAR_STRING_ARRAY(ntps_builder, ntps_list);
    dict = g_variant_builder_end(ntps_builder);
    net_connman_service_call_set_property(serv_obj->srv_proxy, CONNMAN_PROP_TIMESERV_STR".Configuration", g_variant_new("v", dict), NULL, (GAsyncReadyCallback)s_connman_proxy_timeserver_config_cb, serv_obj);
    g_variant_builder_unref (ntps_builder);
    ret = CONNMAN_PROXY_SUCCESS;
safe_exit:
    return ret;
}

int8_t
connman_proxy_service_config_domain(connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char **domain_list)
{
    int8_t ret = CONNMAN_PROXY_FAIL;
    GVariantBuilder *domain_builder = NULL;
    GVariant *dict = NULL;
    connman_proxy_service_info_t *serv_obj = NULL;

    connman_return_val_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL || domain_list == NULL, CONNMAN_PROXY_FAIL);
    serv_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(serv_obj == NULL)
    {
        CONNMAN_LOG_ERROR("Connect Error : Could not find service %s\n", obj_path);
        return CONNMAN_PROXY_FAIL;
    }
    CONNMAN_BUILD_GVAR_STRING_ARRAY(domain_builder, domain_list);
    dict = g_variant_builder_end(domain_builder);
    net_connman_service_call_set_property(serv_obj->srv_proxy, CONNMAN_PROP_DOMAINS_STR".Configuration", g_variant_new("v", dict), NULL, (GAsyncReadyCallback)s_connman_proxy_domain_config_cb, serv_obj);
    g_variant_builder_unref (domain_builder);
    ret = CONNMAN_PROXY_SUCCESS;
safe_exit:
    return ret;
}

int8_t
connman_proxy_service_config_proxy(connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char *method, char *url, char **server_list, char **exclude_list)
{
    int8_t ret = CONNMAN_PROXY_FAIL;
    GVariantBuilder *proxy_builder = NULL;
    GVariant *dict = NULL;
    connman_proxy_service_info_t *serv_obj = NULL;

    connman_return_val_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL || method == NULL, CONNMAN_PROXY_FAIL);

    serv_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(serv_obj == NULL)
    {
        CONNMAN_LOG_ERROR("Connect Error : Could not find service %s\n", obj_path);
        return CONNMAN_PROXY_FAIL;
    }
    proxy_builder = g_variant_builder_new (G_VARIANT_TYPE ("a{sv}"));
    if(proxy_builder)
    {
        g_variant_builder_add (proxy_builder, "{sv}", CONNMAN_PROP_METHOD_STR, g_variant_new_string (method));
        if(strncmp(method, "direct", strlen(method)) == 0)
        {
            /* No need to pass other parameters. Just build and send */
        }
        else if(strncmp(method, "auto", strlen(method)) == 0 && url)
        {
            g_variant_builder_add (proxy_builder, "{sv}", CONNMAN_PROP_URL_STR, g_variant_new_string (url));
        }
        else if(strncmp(method, "manual", strlen(method)) == 0)
        { 
            GVariantBuilder *arr_str_builder = NULL;

            connman_return_val_if_invalid_arg(server_list == NULL, CONNMAN_PROXY_FAIL); /* When set to manual atleast pass the proxy server(s)*/

            CONNMAN_BUILD_GVAR_STRING_ARRAY(arr_str_builder, server_list);
            g_variant_builder_add (proxy_builder, "{sv}", CONNMAN_PROP_SERVERS_STR, g_variant_builder_end(arr_str_builder));
            g_variant_builder_unref (arr_str_builder);

            if(exclude_list)
            {
                CONNMAN_BUILD_GVAR_STRING_ARRAY(arr_str_builder, exclude_list);
                g_variant_builder_add (proxy_builder, "{sv}", CONNMAN_PROP_EXCLUDES_STR, g_variant_builder_end(arr_str_builder));
                g_variant_builder_unref (arr_str_builder);
            }
        }
        dict = g_variant_builder_end (proxy_builder);
        net_connman_service_call_set_property(serv_obj->srv_proxy, CONNMAN_PROP_PROXY_STR".Configuration", g_variant_new("v", dict), NULL, (GAsyncReadyCallback)s_connman_proxy_proxy_config_cb, serv_obj);
        g_variant_builder_unref (proxy_builder);
        ret = CONNMAN_PROXY_SUCCESS;
    }
    else
    {
        CONNMAN_LOG_ERROR("IPV4 Config Error : Couldnt Build  Gvariant for %s\n", obj_path);
    }
safe_exit:
    return ret;
}

void
connman_proxy_service_set_mdns(connman_proxy_handler_t *connman_proxy_handler, char *obj_path, gboolean enable)
{
    connman_proxy_service_info_t *serv_obj = NULL;

    connman_return_if_invalid_arg(connman_proxy_handler == NULL || obj_path == NULL);

    serv_obj = g_hash_table_lookup(connman_proxy_handler->services, obj_path);
    if(serv_obj == NULL)
    {
        CONNMAN_LOG_ERROR("Connect Error : Could not find service %s\n", obj_path);
        return;
    }
    net_connman_service_call_set_property(serv_obj->srv_proxy, CONNMAN_PROP_MDNS_STR".Configuration", g_variant_new("v", g_variant_new_boolean (enable)), NULL, (GAsyncReadyCallback)s_connman_proxy_service_mdns_cb, serv_obj);
}

int8_t
connman_proxy_service_config_ipv6(connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char *method, char *addr, uint8_t prefix_len, char *gw, char *privacy)
{
    int8_t ret = CONNMAN_PROXY_FAIL;
    CONNMAN_LOG_WARNING("!!!!!!!!!! Not Implemented !!!!!!!!!!!!!!!!!!!!");
    CONNMAN_PROXY_UNUSED(connman_proxy_handler);
    CONNMAN_PROXY_UNUSED(obj_path);
    CONNMAN_PROXY_UNUSED(method);
    CONNMAN_PROXY_UNUSED(addr);
    CONNMAN_PROXY_UNUSED(prefix_len);
    CONNMAN_PROXY_UNUSED(gw);
    CONNMAN_PROXY_UNUSED(privacy);
    return ret;
}
