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
 *  File             : connman_proxy_manager_interface.c
 *  Description      : Proxy interface for connman manager
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

#define CONNMAN_PROXY_MGR_PARSE_SYSTEM_PROPERTY(connman_proxy_handler, key, value) \
  if (strcmp (key, CONNMAN_PROP_STATE_STR) == 0)                                   \
    CONNMAN_VAR_GET_STR_COPY (value, &connman_proxy_handler->global_state[0])      \
  else if (strcmp (key, CONNMAN_PROP_OFFLINE_STR) == 0)                            \
    CONNMAN_VAR_GET_BOOL (value, connman_proxy_handler->offline_mode)              \
  else if (strcmp (key, CONNMAN_PROP_SESSION_STR) == 0)                            \
    CONNMAN_VAR_GET_BOOL (value, connman_proxy_handler->session_mode)              \
  else                                                                             \
    {                                                                              \
      CONNMAN_LOG_WARNING ("Unknown Property : %s\n", key);                        \
    }

/**** Static ****/
static void s_connman_proxy_parse_global_system_properties (connman_proxy_handler_t *connman_proxy_handler, GVariant *res);

static void
s_connman_proxy_mgr_register_agent_cb (GDBusProxy *proxy,
                                       GAsyncResult *res,
                                       gpointer user_data)
{
  GError *error = NULL;
  gboolean ret = FALSE;
  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;

  connman_return_if_invalid_arg (connman_proxy_handler == NULL);

  ret = net_connman_manager_call_register_agent_finish (NET_CONNMAN_MANAGER (proxy), res, &error);
  if (ret == TRUE)
    {
      CONNMAN_LOG_INFO ("Agent Registered...\n");
      connman_proxy_handler->agent_registered = TRUE;
    }
  else
    {
      CONNMAN_LOG_ERROR ("Agent Registration failed : %s\n", error->message);
      g_error_free (error);
    }
}

static void
s_connman_proxy_mgr_unregister_agent_cb (GDBusProxy *proxy,
                                         GAsyncResult *res,
                                         gpointer user_data)
{
  GError *error = NULL;
  gboolean ret = FALSE;
  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;

  connman_return_if_invalid_arg (connman_proxy_handler == NULL);

  ret = net_connman_manager_call_unregister_agent_finish (NET_CONNMAN_MANAGER (proxy), res, &error);
  if (ret == TRUE)
    {
      CONNMAN_LOG_INFO ("Agent UnRegistered...\n");
      connman_proxy_handler->agent_registered = FALSE;
    }
  else
    {
      CONNMAN_LOG_ERROR ("Agent UnRegistration failed : %s\n", error->message);
      g_error_free (error);
    }
}

static void
s_connman_proxy_mgr_offline_mode_cb (GDBusProxy *proxy,
                                     GAsyncResult *res,
                                     gboolean enabled,
                                     gpointer user_data)
{
  GError *error = NULL;
  gboolean ret = FALSE;
  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;

  connman_return_if_invalid_arg (connman_proxy_handler == NULL);

  ret = net_connman_manager_call_set_property_finish (NET_CONNMAN_MANAGER (proxy), res, &error);
  if (ret == TRUE)
    {
      CONNMAN_LOG_INFO ("Offline mode %s...\n", enabled ? "enabled" : "disabled");
    }
  else
    {
      CONNMAN_LOG_ERROR ("Couldnt %s Offline mode : %s\n", enabled ? "enable" : "disable", (error && error->message) ? error->message : "Unknown Reason");
      connman_proxy_util_notify_error_cb (connman_proxy_handler, CONNMAN_PROXY_CONFIG_OFFLINE_MODE_ERROR);
      if (error)
        g_error_free (error);
    }
}

static void
s_connman_proxy_mgr_offline_mode_enable_cb (GDBusProxy *proxy,
                                            GAsyncResult *res,
                                            gpointer user_data)
{
  s_connman_proxy_mgr_offline_mode_cb (proxy, res, TRUE, user_data);
}

static void
s_connman_proxy_mgr_offline_mode_disable_cb (GDBusProxy *proxy,
                                             GAsyncResult *res,
                                             gpointer user_data)
{
  s_connman_proxy_mgr_offline_mode_cb (proxy, res, FALSE, user_data);
}

static void
s_connman_proxy_parse_global_system_properties (connman_proxy_handler_t *connman_proxy_handler, GVariant *res)
{
  gsize str_len = 0; /* str_len and str_val To be used in PARSE macro, same name will be used in macro*/
  const gchar *str_val = NULL;

  gchar *key = NULL;
  GVariantIter iter;
  GVariant *value = NULL;

  connman_return_if_invalid_arg (connman_proxy_handler == NULL || res == NULL);

  g_variant_iter_init (&iter, res);
  while (g_variant_iter_next (&iter, "{sv}", &key, &value))
    {
      CONNMAN_PROXY_MGR_PARSE_SYSTEM_PROPERTY (connman_proxy_handler, key, value);

      /*must free data for ourselves*/
      g_variant_unref (value);
      g_free (key);
    }
}

/**** Hidden ****/

/* Manager Signal Handlers*/
void
connman_proxy_mgr_service_changed_cb (NetConnmanManager *object, GVariant *added, GStrv removed, gpointer user_data)
{
  GVariantIter iter;
  GVariant *child = NULL;

  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;

  connman_return_if_invalid_arg (connman_proxy_handler == NULL);

  CONNMAN_PROXY_UNUSED (object);
  CONNMAN_LOG_TRACE ("Service has been Modified\n");

  /* Removed Service*/
  if (removed)
    {
      int i = 0;
      while (removed[i])
        {
          CONNMAN_LOG_INFO ("---------- A Service Has Been Removed ---------- Path : %s\n", removed[i]);
          connman_proxy_service_remove_from_table (connman_proxy_handler, removed[i]);
          i++;
        }
    }
  /* Added/Modified service*/
  if (added)
    {
      CONNMAN_LOG_TRACE ("Type '%s'\n", g_variant_get_type_string (added));
      g_variant_iter_init (&iter, added);
      while ((child = g_variant_iter_next_value (&iter)))
        {
          GVariant *params = NULL;
          char *obj_path = NULL;

          g_variant_get (child, "(o@a{sv})", &obj_path, &params);
          CONNMAN_LOG_TRACE ("Service has been Added/Modified : %s\n", obj_path);
          CONNMAN_LOG_TRACE ("Type '%s'\n", g_variant_get_type_string (params));
          connman_proxy_service_add_new (connman_proxy_handler, obj_path, params);
          g_free (obj_path);
          g_variant_unref (params);
          g_variant_unref (child);
        }
    }
}

void
connman_proxy_mgr_property_changed_cb (NetConnmanManager *object, char *name, GVariant *unboxed_value, gpointer user_data)
{
  gsize str_len = 0; /* str_len and str_val To be used in PARSE macro*/
  const gchar *str_val = NULL;
  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;

  connman_return_if_invalid_arg (connman_proxy_handler == NULL);

  CONNMAN_PROXY_UNUSED (object);
  CONNMAN_LOG_DEBUG ("Manager Property Changed : %s\n", name);
  connman_proxy_util_print_g_variant (name, unboxed_value);
  CONNMAN_PROXY_MGR_PARSE_SYSTEM_PROPERTY (connman_proxy_handler, name, unboxed_value);

  /* Notify Callback */
  if (connman_proxy_handler->cb && connman_proxy_handler->cb->on_update)
    {
      connman_proxy_update_cb_data_t *notify_data = (connman_proxy_update_cb_data_t *) malloc (sizeof (connman_proxy_update_cb_data_t));
      if (NULL == notify_data)
        return;

      if (strcmp (name, CONNMAN_PROP_OFFLINE_STR) == 0)
        {
          notify_data->notify_type = CONNMAN_PROXY_NOTIFY_OFFLINE_UPDATE;
          notify_data->data.offline_enabled = connman_proxy_handler->offline_mode;
        }
      else if (strcmp (name, CONNMAN_PROP_STATE_STR) == 0)
        {
          notify_data->notify_type = CONNMAN_PROXY_NOTIFY_GLOBAL_STATE;
          strncpy (notify_data->data.global_state, connman_proxy_handler->global_state, sizeof (notify_data->data.global_state));
        }
      connman_proxy_handler->cb->on_update (notify_data, connman_proxy_handler->cb->cookie);
    }
}

void
connman_proxy_mgr_technology_added_cb (NetConnmanManager *object, char *path, GVariant *properties, gpointer user_data)
{
  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;
  connman_proxy_technology_info_t *tech_obj = NULL;

  connman_return_if_invalid_arg (connman_proxy_handler == NULL);

  CONNMAN_PROXY_UNUSED (object);
  CONNMAN_LOG_INFO ("Added a new Technology with Path : %s\n", path);
  CONNMAN_UTIL_PRINT_G_VARIENT (path, properties);
  tech_obj = connman_proxy_technology_add_new (connman_proxy_handler, path, properties);

  /* Notify Callback */
  if (tech_obj && connman_proxy_handler->cb && connman_proxy_handler->cb->on_update)
    {
      connman_proxy_update_cb_data_t *notify_data = (connman_proxy_update_cb_data_t *) malloc (sizeof (connman_proxy_update_cb_data_t));
      if (NULL == notify_data)
        return;

      notify_data->notify_type = CONNMAN_PROXY_NOTIFY_TECH_UPDATE;
      notify_data->data.tech.type = g_strdup (tech_obj->type);
      notify_data->data.tech.powered = tech_obj->powered;
      notify_data->data.tech.connected = tech_obj->connected;
      /* TODO tethering not suported yet*/

      connman_proxy_handler->cb->on_update (notify_data, connman_proxy_handler->cb->cookie);
    }
}

void
connman_proxy_mgr_technology_removed_cb (NetConnmanManager *object, char *path, gpointer user_data)
{
  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;
  connman_return_if_invalid_arg (connman_proxy_handler == NULL || path == NULL);

  CONNMAN_PROXY_UNUSED (object);
  CONNMAN_LOG_INFO ("---------- A Technology Has Been Removed ---------- Path : %s\n", path);
  connman_proxy_technology_remove (connman_proxy_handler, path);

  /* Notify Callback */
  if (connman_proxy_handler->cb && connman_proxy_handler->cb->on_update)
    {
      connman_proxy_update_cb_data_t *notify_data = (connman_proxy_update_cb_data_t *) malloc (sizeof (connman_proxy_update_cb_data_t));
      if (NULL == notify_data)
        return;

      notify_data->notify_type = CONNMAN_PROXY_NOTIFY_TECH_UPDATE;
      notify_data->data.tech.type = NULL;

      connman_proxy_handler->cb->on_update (notify_data, connman_proxy_handler->cb->cookie);
    }
}

int8_t
connman_proxy_mgr_get_global_system_properties (connman_proxy_handler_t *connman_proxy_handler)
{
  int8_t ret = -1;
  GVariant *res = NULL;
  GError *err = NULL;

  connman_return_val_if_invalid_arg (connman_proxy_handler == NULL, -1);

  net_connman_manager_call_get_properties_sync (connman_proxy_handler->manager_proxy, &res, NULL, &err);
  if (err)
    {
      CONNMAN_LOG_ERROR ("Get System Properties : %s\n", err->message);
      g_error_free (err);
      return ret;
    }
  else
    {
      s_connman_proxy_parse_global_system_properties (connman_proxy_handler, res);
      CONNMAN_UTIL_PRINT_DICT_ARR (res);
      g_variant_unref (res);
      ret = 0;
    }
  return ret;
}

int8_t
connman_proxy_mgr_get_services (connman_proxy_handler_t *connman_proxy_handler)
{
  int8_t ret = -1;
  GVariant *res = NULL;
  GError *err = NULL;

  connman_return_val_if_invalid_arg (connman_proxy_handler == NULL, -1);

  net_connman_manager_call_get_services_sync (connman_proxy_handler->manager_proxy, &res, NULL, &err);
  if (err)
    {
      CONNMAN_LOG_ERROR ("Get Service : %s\n", err->message);
      g_error_free (err);
      return ret;
    }
  else
    {
      gchar *obj_path = NULL;
      GVariantIter iter;
      GVariant *child = NULL;
      GVariant *params = NULL;
      g_variant_iter_init (&iter, res);
      CONNMAN_LOG_TRACE ("Type '%s'\n", g_variant_get_type_string (res));
      while ((child = g_variant_iter_next_value (&iter)))
        {
          g_variant_get (child, "(o@a{sv})", &obj_path, &params);
          CONNMAN_LOG_TRACE ("Object Path : %s\n", obj_path);
          CONNMAN_LOG_TRACE ("Type '%s'\n", g_variant_get_type_string (params));
          connman_proxy_service_add_new (connman_proxy_handler, obj_path, params);
          g_free (obj_path);
          g_variant_unref (params);
          g_variant_unref (child);
        }
      g_variant_unref (res);
      ret = 0;
    }
  return ret;
}

int8_t
connman_proxy_mgr_get_technologies (connman_proxy_handler_t *connman_proxy_handler)
{
  int8_t ret = -1;
  GVariant *res = NULL;
  GError *err = NULL;

  connman_return_val_if_invalid_arg (connman_proxy_handler == NULL, -1);

  net_connman_manager_call_get_technologies_sync (connman_proxy_handler->manager_proxy, &res, NULL, &err);
  if (err)
    {
      CONNMAN_LOG_ERROR ("Get Service : %s\n", err->message);
      g_error_free (err);
      return ret;
    }
  else
    {
      gchar *obj_path = NULL;
      GVariantIter iter;
      GVariant *child = NULL;
      GVariant *params = NULL;
      g_variant_iter_init (&iter, res);
      CONNMAN_LOG_TRACE ("Type '%s'\n", g_variant_get_type_string (res));
      while ((child = g_variant_iter_next_value (&iter)))
        {
          g_variant_get (child, "(o@a{sv})", &obj_path, &params);
          CONNMAN_LOG_TRACE ("Type '%s'\n", g_variant_get_type_string (params));
          connman_proxy_technology_add_new (connman_proxy_handler, obj_path, params);
          CONNMAN_UTIL_PRINT_DICT_ARR (params);
          g_free (obj_path);
          g_variant_unref (params);
          g_variant_unref (child);
        }
      ret = 0;
      g_variant_unref (res);
    }
  return ret;
}

void
connman_proxy_mgr_register_agent (connman_proxy_handler_t *connman_proxy_handler)
{
  connman_return_if_invalid_arg (connman_proxy_handler == NULL);

  if (connman_proxy_handler->agent_registered == FALSE)
    {
      if (connman_proxy_handler->agent_path == NULL)
        connman_proxy_handler->agent_path = g_strdup_printf ("/net/connman/connmanproxy_%d", getpid ());
      net_connman_manager_call_register_agent (connman_proxy_handler->manager_proxy, connman_proxy_handler->agent_path, NULL, (GAsyncReadyCallback) s_connman_proxy_mgr_register_agent_cb, connman_proxy_handler);
    }
  else
    {
      CONNMAN_LOG_WARNING ("Connman Agent Already Registered\n");
    }
}

void
connman_proxy_mgr_unregister_agent (connman_proxy_handler_t *connman_proxy_handler)
{
  connman_return_if_invalid_arg (connman_proxy_handler == NULL);

  if (connman_proxy_handler->agent_registered == TRUE)
    {
      net_connman_manager_call_unregister_agent (connman_proxy_handler->manager_proxy, connman_proxy_handler->agent_path, NULL, (GAsyncReadyCallback) s_connman_proxy_mgr_unregister_agent_cb, connman_proxy_handler);
    }
  else
    {
      CONNMAN_LOG_WARNING ("Agent is not registered yet\n");
    }
}

void
connman_proxy_mgr_enable_offline_mode (connman_proxy_handler_t *connman_proxy_handler, gboolean enable)
{
  GAsyncReadyCallback offline_cb = (enable) ? (GAsyncReadyCallback) s_connman_proxy_mgr_offline_mode_enable_cb : (GAsyncReadyCallback) s_connman_proxy_mgr_offline_mode_disable_cb;

  connman_return_if_invalid_arg (connman_proxy_handler == NULL);

  net_connman_manager_call_set_property (connman_proxy_handler->manager_proxy, CONNMAN_PROP_OFFLINE_STR, g_variant_new ("v", g_variant_new_boolean (enable)), NULL, offline_cb, connman_proxy_handler);
}

/**** Global ****/
