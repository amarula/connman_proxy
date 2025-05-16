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
 *  File             : connman_proxy_internal.h
 *  Description      : All the internal declarations, macros are defined here
 *
 */

#ifndef __CONNMAN_PROXY_INTERNAL_H
#define __CONNMAN_PROXY_INTERNAL_H

#include <connman_proxy_gdbus_generated.h>

#if defined(__GNUC__) && __GNUC__ >= 4
#define CP_EXPORT __attribute__ ((visibility ("default")))
#else
#define CP_EXPORT
#endif

#define CONNMAN_SERVICE "net.connman"
#define CONNMAN_MANAGER_INTERFACE CONNMAN_SERVICE ".Manager"
#define CONNMAN_SERVICE_INTERFACE CONNMAN_SERVICE ".Service"
#define CONNMAN_TECHNOLOGY_INTERFACE CONNMAN_SERVICE ".Technology"
#define CONNMAN_AGENT_INTERFACE CONNMAN_SERVICE ".Agent"
#define CONNMAN_CLOCK_INTERFACE CONNMAN_SERVICE ".Clock"
#define CONNMAN_MANAGER_PATH "/"

/* Property Names*/
#define CONNMAN_PROP_MTU_STR "MTU"
#define CONNMAN_PROP_URL_STR "URL"
#define CONNMAN_PROP_TYPE_STR "Type"
#define CONNMAN_PROP_NAME_STR "Name"
#define CONNMAN_PROP_IPV4_STR "IPv4"
#define CONNMAN_PROP_IPV6_STR "IPv6"
#define CONNMAN_PROP_MDNS_STR "mDNS"
#define CONNMAN_PROP_STATE_STR "State"
#define CONNMAN_PROP_ERROR_STR "Error"
#define CONNMAN_PROP_PROXY_STR "Proxy"
#define CONNMAN_PROP_METHOD_STR "Method"
#define CONNMAN_PROP_NETMASK_STR "Netmask"
#define CONNMAN_PROP_GATEWAY_STR "Gateway"
#define CONNMAN_PROP_PRIVACY_STR "Privacy"
#define CONNMAN_PROP_SERVERS_STR "Servers"
#define CONNMAN_PROP_DOMAINS_STR "Domains"
#define CONNMAN_PROP_OFFLINE_STR "OfflineMode"
#define CONNMAN_PROP_SESSION_STR "SessionMode"
#define CONNMAN_PROP_ADDRESS_STR "Address"
#define CONNMAN_PROP_POWERED_STR "Powered"
#define CONNMAN_PROP_STRENGTH_STR "Strength"
#define CONNMAN_PROP_SECURITY_STR "Security"
#define CONNMAN_PROP_FAVORITE_STR "Favorite"
#define CONNMAN_PROP_ETHERNET_STR "Ethernet"
#define CONNMAN_PROP_NAMESERV_STR "Nameservers"
#define CONNMAN_PROP_TIMESERV_STR "Timeservers"
#define CONNMAN_PROP_EXCLUDES_STR "Excludes"
#define CONNMAN_PROP_IMMUTABLE_STR "Immutable"
#define CONNMAN_PROP_CONNECTED_STR "Connected"
#define CONNMAN_PROP_TETHERING_STR "Tethering"
#define CONNMAN_PROP_INTERFACE_STR "Interface"
#define CONNMAN_PROP_AUTOCONNECT_STR "AutoConnect"
#define CONNMAN_PROP_PROXYLENTGH_STR "PrefixLength"
#define CONNMAN_PROP_TIME_STR "Time"
#define CONNMAN_PROP_TIMEUPDATES_STR "TimeUpdates"
#define CONNMAN_PROP_TIMEZONE_STR "Timezone"
#define CONNMAN_PROP_TIMEZONEUPDATES_STR "TimezoneUpdates"
#define CONNMAN_PROP_TIMESERVERSYNCED_STR "TimeserverSynced"

#define CONNMAN_PROXY_SAFE_FREE(ptr) \
  if (ptr != NULL)                   \
    {                                \
      free (ptr);                    \
      ptr = NULL;                    \
    }

#define CONNMAN_PROXY_SAFE_GFREE(ptr) \
  if (ptr != NULL)                    \
    {                                 \
      g_free (ptr);                   \
      ptr = NULL;                     \
    }

#define CONNMAN_PROXY_FREE_STR_GLIST(list)                          \
  if (list)                                                         \
    {                                                               \
      g_slist_foreach ((list), (GFunc) connman_proxy_g_free, NULL); \
      g_slist_free (list);                                          \
      (list) = NULL;                                                \
    }

#define CONNMAN_VAR_GET_STR_COPY(val, prop)           \
  {                                                   \
    str_val = g_variant_get_string ((val), &str_len); \
    strncpy ((char *) (prop), str_val, str_len);      \
    (*(prop + str_len)) = '\0';                       \
    CONNMAN_LOG_TRACE ("\tString value: %s\n", prop); \
  }

#define CONNMAN_VAR_GET_STR_DUP(val, prop)                  \
  {                                                         \
    if (prop)                                               \
      {                                                     \
        CONNMAN_LOG_TRACE ("\tString value: %s\n", prop);   \
        g_free (prop);                                      \
      }                                                     \
    (prop) = g_strdup (g_variant_get_string ((val), NULL)); \
    CONNMAN_LOG_TRACE ("\tString value: %s\n", prop);       \
  }

#define CONNMAN_VAR_GET_STR_ARRAY(val, prop)                     \
  {                                                              \
    GVariantIter macro_iter;                                     \
    gchar *macro_value = NULL;                                   \
                                                                 \
    g_variant_iter_init (&macro_iter, val);                      \
    while (g_variant_iter_next (&macro_iter, "s", &macro_value)) \
      {                                                          \
        (prop) = g_slist_append ((prop), macro_value);           \
        CONNMAN_LOG_TRACE ("\tString value: %s\n", macro_value); \
      }                                                          \
  }

#define CONNMAN_VAR_GET_BYTE(val, prop)                            \
  {                                                                \
    prop = g_variant_get_byte (val);                               \
    CONNMAN_LOG_TRACE ("\tByte(Uint8) value: %" PRIu8 "\n", prop); \
  }

#define CONNMAN_VAR_GET_UINT16(val, prop)                      \
  {                                                            \
    prop = g_variant_get_uint16 (val);                         \
    CONNMAN_LOG_TRACE ("\tUint16 value: %" PRIu16 "\n", prop); \
  }

#define CONNMAN_VAR_GET_UINT64(val, prop)                      \
  {                                                            \
    prop = g_variant_get_uint64 (val);                         \
    CONNMAN_LOG_TRACE ("\tUint64 value: %" PRIu64 "\n", prop); \
  }

#define CONNMAN_VAR_GET_BOOL(val, prop)                              \
  {                                                                  \
    prop = g_variant_get_boolean (val);                              \
    CONNMAN_LOG_TRACE ("\tBool value: %s\n", (prop) ? "Yes" : "No"); \
  }

#define connman_return_if_invalid_arg(cond)                           \
  if ((cond))                                                         \
    {                                                                 \
      CONNMAN_LOG_ERROR ("xxxxxxxxxx Invalid Argument xxxxxxxxxx\n"); \
      return;                                                         \
    }
#define connman_return_val_if_invalid_arg(cond, ret)                  \
  if ((cond))                                                         \
    {                                                                 \
      CONNMAN_LOG_ERROR ("xxxxxxxxxx Invalid Argument xxxxxxxxxx\n"); \
      return (ret);                                                   \
    }

/* Utils APIs */
void connman_proxy_util_print_array_of_dict (GVariant *res);
void connman_proxy_util_print_array_of_string (GVariant *res);
void connman_proxy_util_print_custom (GVariant *res);
void connman_proxy_g_free (gpointer data, gpointer user_data);
void connman_proxy_util_notify_error_cb (connman_proxy_handler_t *connman_proxy_handler, connman_proxy_error_type_t error_code);
void connman_proxy_util_notify_connman_service_cb (connman_proxy_handler_t *connman_proxy_handler, gboolean available);

/* Clock APIs */
int8_t connman_proxy_clock_get_properties (connman_proxy_handler_t *connman_proxy_handler);
void connman_proxy_clock_property_changed_cb (NetConnmanClock *object, char *name, GVariant *value, gpointer user_data);
void connman_proxy_clock_set_time (connman_proxy_handler_t *connman_proxy_handler, guint time);
void connman_proxy_clock_set_time_updates (connman_proxy_handler_t *connman_proxy_handler, char *time_updates);
void connman_proxy_clock_set_timezone (connman_proxy_handler_t *connman_proxy_handler, char *timezone);
void connman_proxy_clock_set_timezone_updates (connman_proxy_handler_t *connman_proxy_handler, char *timezone_updates);
int8_t connman_proxy_clock_set_timeserver (connman_proxy_handler_t *connman_proxy_handler, char **timeserver);

/* Service APIs */
void connman_proxy_service_init (connman_proxy_handler_t *connman_proxy_handler);
void connman_proxy_service_deinit (connman_proxy_handler_t *connman_proxy_handler);
void connman_proxy_service_connect (connman_proxy_handler_t *connman_proxy_handler, char *obj_path);
void connman_proxy_service_disconnect (connman_proxy_handler_t *connman_proxy_handler, char *obj_path);
void connman_proxy_service_remove (connman_proxy_handler_t *connman_proxy_handler, char *service_name);
void connman_proxy_service_remove_from_table (connman_proxy_handler_t *connman_proxy_handler, char *service_name);
void connman_proxy_service_set_autoconnect (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, gboolean autoconnect);
void connman_proxy_service_set_mdns (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, gboolean enable);
void connman_proxy_service_property_changed_cb (NetConnmanService *object, connman_proxy_handler_t *connman_proxy_handler, char *name, GVariant *value, gpointer user_data);
int8_t connman_proxy_service_add_new (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, GVariant *params);
int8_t connman_proxy_service_config_ipv4 (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char *method, char *addr, char *mask, char *gw);
int8_t connman_proxy_service_config_ipv6 (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char *method, char *addr, uint8_t prefix_len, char *gw, char *privacy);
int8_t connman_proxy_service_config_proxy (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char *method, char *url, char **server_list, char **exclude_list);
int8_t connman_proxy_service_config_nameserver (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char **nameserver_list);
int8_t connman_proxy_service_config_timeserver (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char **timeserver_list);
int8_t connman_proxy_service_config_domain (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char **domain_list);

/* manager APIs */
int8_t connman_proxy_mgr_get_global_system_properties (connman_proxy_handler_t *connman_proxy_handler);
int8_t connman_proxy_mgr_get_technologies (connman_proxy_handler_t *connman_proxy_handler);
int8_t connman_proxy_mgr_get_services (connman_proxy_handler_t *connman_proxy_handler);

void connman_proxy_mgr_property_changed_cb (NetConnmanManager *object, char *name, GVariant *value, gpointer user_data);
void connman_proxy_mgr_technology_added_cb (NetConnmanManager *object, char *path, GVariant *properties, gpointer user_data);
void connman_proxy_mgr_technology_removed_cb (NetConnmanManager *object, char *path, gpointer user_data);
void connman_proxy_mgr_service_changed_cb (NetConnmanManager *object, GVariant *added, GStrv removed, gpointer user_data);
void connman_proxy_mgr_register_agent (connman_proxy_handler_t *connman_proxy_handler);
void connman_proxy_mgr_unregister_agent (connman_proxy_handler_t *connman_proxy_handler);

void connman_proxy_mgr_enable_offline_mode (connman_proxy_handler_t *connman_proxy_handler, gboolean enable);

/* Technology APIs */
void connman_proxy_technology_scan (connman_proxy_handler_t *connman_proxy_handler, char *obj_path);
void connman_proxy_technology_cleanup (gpointer free_obj, gpointer user_data);
void connman_proxy_technology_remove (connman_proxy_handler_t *connman_proxy_handler, char *obj_path);
void connman_proxy_technology_set_power (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, gboolean powered);
void connman_proxy_technology_property_changed_cb (NetConnmanTechnology *object, connman_proxy_handler_t *connman_proxy_handler, char *name, GVariant *value, gpointer user_data);
connman_proxy_technology_info_t *connman_proxy_technology_add_new (connman_proxy_handler_t *connman_proxy_handler, gchar *obj_path, GVariant *res);
connman_proxy_technology_info_t *connman_proxy_technology_find_by_path (connman_proxy_handler_t *connman_proxy_handler, const gchar *object_path);

/* Agent managr APIs*/
gboolean connman_mgr_agent_init (connman_proxy_handler_t *connman_proxy_handler);
void connman_mgr_agent_deinit (connman_proxy_handler_t *connman_proxy_handler);

#endif /*__CONNMAN_PROXY_INTERNAL_H */
