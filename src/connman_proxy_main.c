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
 *  File             : connman_proxy_main.c
 *  Description      : All Main interface are deinfed here. Contains all public APIs
 *
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "connman_proxy.h"
#include "connman_proxy_internal.h"

/**** Static ****/

static void
s_monitor_dbus_signals_cb (GDBusConnection *connection,
                           const gchar *sender_name,
                           const gchar *object_path,
                           const gchar *interface_name,
                           const gchar *signal_name,
                           GVariant *parameters,
                           gpointer user_data)
{
  GVariant *val = NULL;
  gchar *string = NULL;

  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;

  g_variant_get (parameters, "(sv)", &string, &val);

  CONNMAN_UTIL_PRINT_G_VARIENT ((char *) object_path, parameters);

  if (g_strcmp0 (interface_name, CONNMAN_MANAGER_INTERFACE) == 0)
    {
      connman_proxy_mgr_property_changed_cb (connman_proxy_handler->manager_proxy, string, val, user_data);
    }
  else if (g_strcmp0 (interface_name, CONNMAN_CLOCK_INTERFACE) == 0)
    {
      connman_proxy_clock_property_changed_cb (connman_proxy_handler->clock_proxy, string, val, user_data);
    }
  else if (g_strcmp0 (interface_name, CONNMAN_SERVICE_INTERFACE) == 0)
    {
      connman_proxy_service_info_t *serv_obj = NULL;
      serv_obj = g_hash_table_lookup (connman_proxy_handler->services, object_path);
      if (serv_obj == NULL)
        {
          CONNMAN_LOG_ERROR ("Connect Error : Could not find service %s\n", object_path);
          goto safe_exit;
        }
      connman_proxy_service_property_changed_cb (serv_obj->srv_proxy, connman_proxy_handler, string, val, serv_obj);
    }
  else if (g_strcmp0 (interface_name, CONNMAN_TECHNOLOGY_INTERFACE) == 0)
    {
      connman_proxy_technology_info_t *tech_obj = NULL;
      tech_obj = connman_proxy_technology_find_by_path (connman_proxy_handler, object_path);
      if (tech_obj)
        connman_proxy_technology_property_changed_cb (tech_obj->tech_proxy, connman_proxy_handler, string, val, tech_obj);
      else
        {
          CONNMAN_LOG_ERROR ("Connect Error : Could not find technology %s\n", object_path);
          goto safe_exit;
        }
    }
  else
    {
      CONNMAN_LOG_WARNING ("!!!!!!! Not Handled !!!!!!!!  Sender : %s , object_path = %s, interface_name : %s, signal_name : %s\n", sender_name, object_path, interface_name, signal_name);
    }

safe_exit:
  g_free (string);
  g_variant_unref (val);
}

static void
s_on_name_appeared (GDBusConnection *connection,
                    const gchar *name,
                    const gchar *name_owner,
                    gpointer user_data)
{
  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;

  CONNMAN_LOG_INFO ("Connman Service is available now...\n");
  connman_proxy_handler->service_available = TRUE;
  connman_proxy_handler->tech_added_sid = g_signal_connect (connman_proxy_handler->manager_proxy, "technology-added", G_CALLBACK (connman_proxy_mgr_technology_added_cb), connman_proxy_handler);
  connman_proxy_handler->tech_removed_sid = g_signal_connect (connman_proxy_handler->manager_proxy, "technology-removed", G_CALLBACK (connman_proxy_mgr_technology_removed_cb), connman_proxy_handler);
  connman_proxy_handler->service_changed_sid = g_signal_connect (connman_proxy_handler->manager_proxy, "services-changed", G_CALLBACK (connman_proxy_mgr_service_changed_cb), connman_proxy_handler);

  /* Subscribe all PropertyChange event on dbus connection insteadof connecting "property-changed" to individual connection, this will make sure we wont miss any property-changed event*/
  connman_proxy_handler->subscription_id = g_dbus_connection_signal_subscribe (connman_proxy_handler->connection,
                                                                               CONNMAN_SERVICE,
                                                                               NULL,
                                                                               "PropertyChanged",
                                                                               NULL,
                                                                               NULL,
                                                                               G_DBUS_SIGNAL_FLAGS_NONE,
                                                                               s_monitor_dbus_signals_cb,
                                                                               connman_proxy_handler,
                                                                               NULL);

  connman_proxy_clock_get_properties (connman_proxy_handler);
  connman_proxy_mgr_get_global_system_properties (connman_proxy_handler);
  connman_proxy_mgr_get_technologies (connman_proxy_handler);
  connman_proxy_service_init (connman_proxy_handler);
  connman_proxy_mgr_get_services (connman_proxy_handler);
  connman_proxy_mgr_register_agent (connman_proxy_handler);

  /* Notify Callback*/
  connman_proxy_util_notify_connman_service_cb (connman_proxy_handler, TRUE);

  return;
}

static void
s_on_name_vanished (GDBusConnection *connection,
                    const gchar *name,
                    gpointer user_data)
{
  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;

  CONNMAN_LOG_WARNING ("Connman Service is un-available now...\n");
  connman_proxy_handler->service_available = FALSE;

  /* Unsubscripe all property changed notifications first */
  if (connman_proxy_handler->subscription_id)
    {
      g_dbus_connection_signal_unsubscribe (connman_proxy_handler->connection, connman_proxy_handler->subscription_id);
      connman_proxy_handler->subscription_id = 0;
    }

  /* Remove signal handlers*/
  if (connman_proxy_handler->tech_removed_sid)
    {
      g_signal_handler_disconnect (connman_proxy_handler->manager_proxy, connman_proxy_handler->tech_removed_sid);
      connman_proxy_handler->tech_removed_sid = 0;
    }
  if (connman_proxy_handler->tech_added_sid)
    {
      g_signal_handler_disconnect (connman_proxy_handler->manager_proxy, connman_proxy_handler->tech_added_sid);
      connman_proxy_handler->tech_added_sid = 0;
    }
  if (connman_proxy_handler->service_changed_sid)
    {
      g_signal_handler_disconnect (connman_proxy_handler->manager_proxy, connman_proxy_handler->service_changed_sid);
      connman_proxy_handler->service_changed_sid = 0;
    }

  /* Notify Callback with service availability status*/
  connman_proxy_util_notify_connman_service_cb (connman_proxy_handler, FALSE);
}

/**** Hidden ****/
/**** Global ****/

CP_EXPORT connman_proxy_handler_t *
connman_proxy_init (connman_proxy_callback_handlers_t *cb)
{
  connman_proxy_handler_t *connman_proxy_handler = NULL;
  GError *err = NULL;

  connman_proxy_handler = g_new0 (connman_proxy_handler_t, 1);
  if (connman_proxy_handler == NULL)
    {
      CONNMAN_LOG_ERROR ("xxxxxxxxxx Malloc Error xxxxxxxxxx\n");
      goto safe_exit;
    }

  connman_proxy_handler->connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM, NULL, &err);
  if (connman_proxy_handler->connection == NULL)
    {
      CONNMAN_LOG_ERROR ("xxxxxxxxxx Could Not get G_BUS System connection xxxxxxxxxx : %s\n", err ? err->message : "Unknown Reason");
      CONNMAN_PROXY_SAFE_GFREE (connman_proxy_handler);
      goto safe_exit;
    }

  /* Create Manager Proxy and register with all manager signals*/
  connman_proxy_handler->manager_proxy = net_connman_manager_proxy_new_sync (connman_proxy_handler->connection, G_DBUS_PROXY_FLAGS_NONE, CONNMAN_SERVICE, CONNMAN_MANAGER_PATH, NULL, &err);
  if (connman_proxy_handler->manager_proxy == NULL)
    {
      CONNMAN_LOG_ERROR ("xxxxxxxxxx Could Not get connman manager proxy xxxxxxxxxx : %s\n", err ? err->message : "Unknown Reason");
      g_object_unref (connman_proxy_handler->connection);
      CONNMAN_PROXY_SAFE_GFREE (connman_proxy_handler);
      goto safe_exit;
    }

  connman_proxy_handler->clock_proxy = net_connman_clock_proxy_new_sync (connman_proxy_handler->connection, G_DBUS_PROXY_FLAGS_NONE, CONNMAN_SERVICE, CONNMAN_MANAGER_PATH, NULL, &err);
  if (connman_proxy_handler->clock_proxy == NULL)
    {
      CONNMAN_LOG_ERROR ("xxxxxxxxxx Could Not get connman clock proxy xxxxxxxxxx : %s\n", err ? err->message : "Unknown Reason");
      g_object_unref (connman_proxy_handler->connection);
      CONNMAN_PROXY_SAFE_GFREE (connman_proxy_handler);
      goto safe_exit;
    }

  connman_proxy_handler->clock = g_new0 (connman_proxy_clock_info_t, 1);
  if (connman_proxy_handler->clock == NULL)
    {
      CONNMAN_LOG_ERROR ("xxxxxxxxxx Malloc Error xxxxxxxxxx\n");
      goto safe_exit;
    }

  connman_proxy_handler->watcher_id = g_bus_watch_name (G_BUS_TYPE_SYSTEM,
                                                        CONNMAN_SERVICE,
                                                        G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_NONE,
                                                        s_on_name_appeared,
                                                        s_on_name_vanished,
                                                        connman_proxy_handler,
                                                        NULL);
  if (connman_proxy_handler->watcher_id == 0)
    {
      CONNMAN_LOG_ERROR ("xxxxxxxxxx Error setting watcher for %s xxxxxxxxxx\n", CONNMAN_SERVICE);
      g_object_unref (connman_proxy_handler->manager_proxy);
      g_object_unref (connman_proxy_handler->connection);
      CONNMAN_PROXY_SAFE_GFREE (connman_proxy_handler);
      goto safe_exit;
    }

  connman_proxy_handler->loop = g_main_loop_new (NULL, FALSE);
  if (connman_proxy_handler->loop == NULL)
    {
      CONNMAN_LOG_ERROR ("xxxxxxxxxx Could Not get connman manager proxy xxxxxxxxxx : %s\n", err ? err->message : "Unknown Reason");
      g_bus_unwatch_name (connman_proxy_handler->watcher_id);
      g_object_unref (connman_proxy_handler->manager_proxy);
      g_object_unref (connman_proxy_handler->connection);
      CONNMAN_PROXY_SAFE_GFREE (connman_proxy_handler);
      goto safe_exit;
    }

  /* Manager for Connman agent.*/
  if (connman_mgr_agent_init (connman_proxy_handler) == FALSE)
    {
      CONNMAN_LOG_WARNING ("!!!!!!!!!! Connman Agent manager Initialization Failed !!!!!!!!!! : Wireless Network Interfaces Will not work\n");
    }
  connman_proxy_handler->cb = cb;

  /* Set default state as offline*/
  strcpy (connman_proxy_handler->global_state, "Offline");

safe_exit:
  return connman_proxy_handler;
}

CP_EXPORT void
connman_proxy_deinit (connman_proxy_handler_t *connman_proxy_handler)
{
  if (connman_proxy_handler)
    {
      connman_mgr_agent_deinit (connman_proxy_handler);

      /* Unsubscripe all property changed notifications first */
      if (connman_proxy_handler->subscription_id)
        g_dbus_connection_signal_unsubscribe (connman_proxy_handler->connection, connman_proxy_handler->subscription_id);

      /* Remove signal handlers*/
      if (connman_proxy_handler->tech_removed_sid)
        g_signal_handler_disconnect (connman_proxy_handler->manager_proxy, connman_proxy_handler->tech_removed_sid);
      if (connman_proxy_handler->tech_added_sid)
        g_signal_handler_disconnect (connman_proxy_handler->manager_proxy, connman_proxy_handler->tech_added_sid);
      if (connman_proxy_handler->service_changed_sid)
        g_signal_handler_disconnect (connman_proxy_handler->manager_proxy, connman_proxy_handler->service_changed_sid);

      /* Cleanup Technologies*/
      if (connman_proxy_handler->technologies)
        {
          g_slist_foreach (connman_proxy_handler->technologies, (GFunc) connman_proxy_technology_cleanup, NULL);
          g_slist_free (connman_proxy_handler->technologies);
        }

      connman_proxy_service_deinit (connman_proxy_handler);

      if (connman_proxy_handler->watcher_id)
        g_bus_unwatch_name (connman_proxy_handler->watcher_id);
      g_object_unref (connman_proxy_handler->manager_proxy);
      g_object_unref (connman_proxy_handler->connection);

      if (connman_proxy_handler->loop)
        {
          g_main_loop_unref (connman_proxy_handler->loop);
          connman_proxy_handler->loop = NULL;
        }
      CONNMAN_PROXY_SAFE_GFREE (connman_proxy_handler);
    }
}

CP_EXPORT void
connman_proxy_set_offline (connman_proxy_handler_t *connman_proxy_handler, gboolean offline_mode)
{
  connman_proxy_mgr_enable_offline_mode (connman_proxy_handler, offline_mode);
}

CP_EXPORT void
connman_proxy_scan_technology (connman_proxy_handler_t *connman_proxy_handler, char *obj_path)
{
  connman_proxy_technology_scan (connman_proxy_handler, obj_path);
}

CP_EXPORT void
connman_proxy_set_technology_power (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, gboolean powered)
{
  connman_proxy_technology_set_power (connman_proxy_handler, obj_path, powered);
}

CP_EXPORT void
connman_proxy_set_service_autoconnect (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, gboolean autoconnect)
{
  connman_proxy_service_set_autoconnect (connman_proxy_handler, obj_path, autoconnect);
}

CP_EXPORT void
connman_proxy_connect_service (connman_proxy_handler_t *connman_proxy_handler, char *obj_path)
{
  connman_proxy_service_connect (connman_proxy_handler, obj_path);
}

CP_EXPORT void
connman_proxy_disconnect_service (connman_proxy_handler_t *connman_proxy_handler, char *obj_path)
{
  connman_proxy_service_disconnect (connman_proxy_handler, obj_path);
}

CP_EXPORT void
connman_proxy_remove_service (connman_proxy_handler_t *connman_proxy_handler, char *obj_path)
{
  connman_proxy_service_remove (connman_proxy_handler, obj_path);
}

CP_EXPORT int8_t
connman_proxy_configure_ipv4 (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char *method, char *addr, char *mask, char *gw)
{
  return connman_proxy_service_config_ipv4 (connman_proxy_handler, obj_path, method, addr, mask, gw);
}

CP_EXPORT int8_t
connman_proxy_configure_ipv6 (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char *method, char *addr, uint8_t prefix_len, char *gw, char *privacy)
{
  return connman_proxy_service_config_ipv6 (connman_proxy_handler, obj_path, method, addr, prefix_len, gw, privacy);
}

CP_EXPORT int8_t
connman_proxy_configure_proxy (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char *method, char *url, char **server_list, char **exclude_list)
{
  return connman_proxy_service_config_proxy (connman_proxy_handler, obj_path, method, url, server_list, exclude_list);
}

CP_EXPORT int8_t
connman_proxy_configure_nameserver (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char **nameserver_list)
{
  return connman_proxy_service_config_nameserver (connman_proxy_handler, obj_path, nameserver_list);
}

CP_EXPORT int8_t
connman_proxy_configure_timeserver (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char **timeserver_list)
{
  return connman_proxy_service_config_timeserver (connman_proxy_handler, obj_path, timeserver_list);
}

CP_EXPORT int8_t
connman_proxy_configure_domain (connman_proxy_handler_t *connman_proxy_handler, char *obj_path, char **domain_list)
{
  return connman_proxy_service_config_domain (connman_proxy_handler, obj_path, domain_list);
}

CP_EXPORT void
connman_proxy_set_clock_time (connman_proxy_handler_t *connman_proxy_handler, uint64_t time)
{
  return connman_proxy_clock_set_time (connman_proxy_handler, time);
}

CP_EXPORT void
connman_proxy_set_clock_time_updates (connman_proxy_handler_t *connman_proxy_handler, char *time_updates)
{
  return connman_proxy_clock_set_time_updates (connman_proxy_handler, time_updates);
}

CP_EXPORT void
connman_proxy_set_clock_timezone (connman_proxy_handler_t *connman_proxy_handler, char *timezone)
{
  return connman_proxy_clock_set_timezone (connman_proxy_handler, timezone);
}

CP_EXPORT void
connman_proxy_set_clock_timezone_updates (connman_proxy_handler_t *connman_proxy_handler, char *timezone_updates)
{
  return connman_proxy_clock_set_timezone_updates (connman_proxy_handler, timezone_updates);
}

CP_EXPORT int8_t
connman_proxy_set_clock_timeserver (connman_proxy_handler_t *connman_proxy_handler, char **timeserver_list)
{
  return connman_proxy_clock_set_timeserver (connman_proxy_handler, timeserver_list);
}
