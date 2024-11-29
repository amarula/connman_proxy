/*
 *  Copyright 2024, Andrea Ricchi <andrea.ricchi@amarulasolutions.com>, All rights reserved.
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
 *  Author(s)        : Andrea Ricchi <andrea.ricchi@amarulasolutions.com>
 *  File             : connman_proxy_clock_interface.c
 *  Description      : Proxy Interface sofr connman service object
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

#define CONNMAN_PROXY_CLOCK_PARSE_PROPERTY(clock_obj, key, value)                                      \
  if (strcmp (key, CONNMAN_PROP_TIME_STR) == 0)                                                        \
    CONNMAN_VAR_GET_UINT64 (value, clock_obj->time)                                                    \
  else if (strcmp (key, CONNMAN_PROP_TIMEUPDATES_STR) == 0)                                            \
    CONNMAN_VAR_GET_STR_COPY (value, &clock_obj->time_updates[0])                                      \
  else if (strcmp (key, CONNMAN_PROP_TIMEZONE_STR) == 0)                                               \
    CONNMAN_VAR_GET_STR_DUP (value, clock_obj->timezone)                                               \
  else if (strcmp (key, CONNMAN_PROP_TIMEZONEUPDATES_STR) == 0)                                        \
    CONNMAN_VAR_GET_STR_COPY (value, &clock_obj->timezone_updates[0])                                  \
  else if (strcmp (key, CONNMAN_PROP_TIMESERV_STR) == 0)                                               \
    {                                                                                                  \
      CONNMAN_PROXY_FREE_STR_GLIST (clock_obj->timeservers);                                           \
      CONNMAN_VAR_GET_STR_ARRAY (value, clock_obj->timeservers)                                        \
    }                                                                                                  \
  else                                                                                                 \
    {                                                                                                  \
      CONNMAN_LOG_WARNING ("Unknown Property : %s Type %s\n", key, g_variant_get_type_string (value)); \
    }

#define CONNMAN_BUILD_GVAR_STRING_ARRAY(builder, value_list)                  \
  {                                                                           \
    int8_t i = 0;                                                             \
    builder = g_variant_builder_new (G_VARIANT_TYPE ("as"));                  \
    if (builder == NULL)                                                      \
      {                                                                       \
        CONNMAN_LOG_ERROR ("Could not build String Array Variant Builder\n"); \
        goto safe_exit;                                                       \
      }                                                                       \
    while (value_list[i])                                                     \
      {                                                                       \
        CONNMAN_LOG_DEBUG ("%d : Append String %s\n", i, value_list[i]);      \
        g_variant_builder_add (builder, "s", value_list[i]);                  \
        i++;                                                                  \
      }                                                                       \
  }

/**** Static ****/

static void
s_connman_proxy_parse_clock_properties (connman_proxy_handler_t *connman_proxy_handler, GVariant *res)
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
      CONNMAN_LOG_INFO ("RICCHI - %s \n", key);
      CONNMAN_PROXY_CLOCK_PARSE_PROPERTY (connman_proxy_handler->clock, key, value);

      /*must free data for ourselves*/
      g_variant_unref (value);
      g_free (key);
    }
}

static void
s_connman_proxy_time_config_cb (GDBusProxy *proxy,
                                GAsyncResult *res,
                                connman_proxy_handler_t *connman_proxy_handler)
{
  GError *error = NULL;
  gboolean ret = FALSE;

  ret = net_connman_clock_call_set_property_finish (NET_CONNMAN_CLOCK (proxy), res, &error);
  if (ret == TRUE)
    {
      CONNMAN_LOG_INFO ("Configured Time For Clock\n");
    }
  else
    {
      CONNMAN_LOG_ERROR ("Could Not Configured Time For Clock : %s\n", error->message);
      connman_proxy_util_notify_error_cb (connman_proxy_handler, CONNMAN_PROXY_CONFIG_CLOCK_ERROR);
      if (error)
        g_error_free (error);
    }
  if (connman_proxy_handler->user_data_1)
    {
      g_free (connman_proxy_handler->user_data_1);
      connman_proxy_handler->user_data_1 = NULL;
    }
}

static void
s_connman_proxy_time_updates_config_cb (GDBusProxy *proxy,
                                        GAsyncResult *res,
                                        connman_proxy_handler_t *connman_proxy_handler)
{
  GError *error = NULL;
  gboolean ret = FALSE;

  ret = net_connman_clock_call_set_property_finish (NET_CONNMAN_CLOCK (proxy), res, &error);
  if (ret == TRUE)
    {
      CONNMAN_LOG_INFO ("Configured Time Updates For Clock\n");
    }
  else
    {
      CONNMAN_LOG_ERROR ("Could Not Configured Time Updates For Clock : %s\n", error->message);
      connman_proxy_util_notify_error_cb (connman_proxy_handler, CONNMAN_PROXY_CONFIG_CLOCK_ERROR);
      if (error)
        g_error_free (error);
    }
  if (connman_proxy_handler->user_data_1)
    {
      g_free (connman_proxy_handler->user_data_1);
      connman_proxy_handler->user_data_1 = NULL;
    }
}

static void
s_connman_proxy_timezone_config_cb (GDBusProxy *proxy,
                                    GAsyncResult *res,
                                    connman_proxy_handler_t *connman_proxy_handler)
{
  GError *error = NULL;
  gboolean ret = FALSE;

  ret = net_connman_clock_call_set_property_finish (NET_CONNMAN_CLOCK (proxy), res, &error);
  if (ret == TRUE)
    {
      CONNMAN_LOG_INFO ("Configured Timezone For Clock\n");
    }
  else
    {
      CONNMAN_LOG_ERROR ("Could Not Configured Timezone For Clock : %s\n", error->message);
      connman_proxy_util_notify_error_cb (connman_proxy_handler, CONNMAN_PROXY_CONFIG_CLOCK_ERROR);
      if (error)
        g_error_free (error);
    }
  if (connman_proxy_handler->user_data_1)
    {
      g_free (connman_proxy_handler->user_data_1);
      connman_proxy_handler->user_data_1 = NULL;
    }
}

static void
s_connman_proxy_timezone_updates_config_cb (GDBusProxy *proxy,
                                            GAsyncResult *res,
                                            connman_proxy_handler_t *connman_proxy_handler)
{
  GError *error = NULL;
  gboolean ret = FALSE;

  ret = net_connman_clock_call_set_property_finish (NET_CONNMAN_CLOCK (proxy), res, &error);
  if (ret == TRUE)
    {
      CONNMAN_LOG_INFO ("Configured Timezone Updates For Clock\n");
    }
  else
    {
      CONNMAN_LOG_ERROR ("Could Not Configured Timezone Updates For Clock : %s\n", error->message);
      connman_proxy_util_notify_error_cb (connman_proxy_handler, CONNMAN_PROXY_CONFIG_CLOCK_ERROR);
      if (error)
        g_error_free (error);
    }
  if (connman_proxy_handler->user_data_1)
    {
      g_free (connman_proxy_handler->user_data_1);
      connman_proxy_handler->user_data_1 = NULL;
    }
}

static void
s_connman_proxy_timeserver_config_cb (GDBusProxy *proxy,
                                      GAsyncResult *res,
                                      connman_proxy_handler_t *connman_proxy_handler)
{
  GError *error = NULL;
  gboolean ret = FALSE;
  ret = net_connman_clock_call_set_property_finish (NET_CONNMAN_CLOCK (proxy), res, &error);
  if (ret == TRUE)
    {
      CONNMAN_LOG_INFO ("Configured Timeservers For Clock\n");
    }
  else
    {
      CONNMAN_LOG_ERROR ("Could Not Configure Timeservers For Clock : %s\n", error->message);
      connman_proxy_util_notify_error_cb (connman_proxy_handler, CONNMAN_PROXY_CONFIG_NTPS_ERROR);
      if (error)
        g_error_free (error);
    }
  if (connman_proxy_handler->user_data_1)
    {
      g_free (connman_proxy_handler->user_data_1);
      connman_proxy_handler->user_data_1 = NULL;
    }
}

static void
s_connman_proxy_srv_entry_free (gpointer data)
{
  connman_proxy_clock_info_t *clock_obj = data;

  if (clock_obj != NULL)
    {
      CONNMAN_PROXY_SAFE_FREE (clock_obj->timezone);
      CONNMAN_PROXY_FREE_STR_GLIST (clock_obj->timeservers);

      /*Clean up main object*/
      free (clock_obj);
    }
  return;
}

/**** Hidden ****/
void
connman_proxy_clock_property_changed_cb (NetConnmanClock *object, char *name, GVariant *unboxed_value, gpointer user_data)
{
  gsize str_len = 0; /* str_len and str_val To be used in PARSE macro, same name will be used in macro*/
  const gchar *str_val = NULL;
  connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *) user_data;

  connman_return_if_invalid_arg (connman_proxy_handler == NULL);
  connman_return_if_invalid_arg (connman_proxy_handler->clock == NULL);
  CONNMAN_PROXY_UNUSED (object);

  CONNMAN_LOG_DEBUG ("Clock Property Changed : %s\n", name);
  connman_proxy_util_print_g_variant (name, unboxed_value);
  CONNMAN_PROXY_CLOCK_PARSE_PROPERTY (connman_proxy_handler->clock, name, unboxed_value)

  /* Notify Callback */
  if (connman_proxy_handler->cb && connman_proxy_handler->cb->on_update)
    {
      connman_proxy_update_cb_data_t *notify_data = (connman_proxy_update_cb_data_t *) malloc (sizeof (connman_proxy_update_cb_data_t));
      if (NULL == notify_data)
        return;

      notify_data->notify_type = CONNMAN_PROXY_NOTIFY_CLOCK_UPDATE;

      notify_data->data.clock.time = connman_proxy_handler->clock->time;
      strncpy (notify_data->data.clock.time_updates, connman_proxy_handler->clock->time_updates, sizeof (notify_data->data.clock.time_updates));
      notify_data->data.clock.timezone = connman_proxy_handler->clock->timezone ? g_strdup (connman_proxy_handler->clock->timezone) : NULL;
      strncpy (notify_data->data.clock.timezone_updates, connman_proxy_handler->clock->timezone_updates, sizeof (notify_data->data.clock.timezone_updates));

      connman_proxy_handler->cb->on_update (notify_data, connman_proxy_handler->cb->cookie);
    }
}

/* All set property related */
int8_t
connman_proxy_clock_get_properties (connman_proxy_handler_t *connman_proxy_handler)
{
  int8_t ret = -1;
  GVariant *res = NULL;
  GError *err = NULL;

  connman_return_val_if_invalid_arg (connman_proxy_handler == NULL, -1);

  net_connman_clock_call_get_properties_sync (connman_proxy_handler->clock_proxy, &res, NULL, &err);
  if (err)
    {
      CONNMAN_LOG_ERROR ("Get Clock Properties : %s\n", err->message);
      g_error_free (err);
      return ret;
    }
  else
    {
      s_connman_proxy_parse_clock_properties (connman_proxy_handler, res);
      CONNMAN_UTIL_PRINT_DICT_ARR (res);
      g_variant_unref (res);
      ret = 0;
    }
  return ret;
}

void
connman_proxy_clock_set_time (connman_proxy_handler_t *connman_proxy_handler, guint time)
{
  connman_return_if_invalid_arg (connman_proxy_handler == NULL);

  net_connman_clock_call_set_property (connman_proxy_handler->clock_proxy, CONNMAN_PROP_TIME_STR, g_variant_new ("v", g_variant_new_uint64 (time)), NULL, (GAsyncReadyCallback) s_connman_proxy_time_config_cb, connman_proxy_handler);
}

void
connman_proxy_clock_set_time_updates (connman_proxy_handler_t *connman_proxy_handler, char *time_updates)
{
  connman_return_if_invalid_arg (connman_proxy_handler == NULL || time_updates == NULL);

  net_connman_clock_call_set_property (connman_proxy_handler->clock_proxy, CONNMAN_PROP_TIMEUPDATES_STR, g_variant_new ("v", g_variant_new_string (time_updates)), NULL, (GAsyncReadyCallback) s_connman_proxy_time_updates_config_cb, connman_proxy_handler);
}

void
connman_proxy_clock_set_timezone (connman_proxy_handler_t *connman_proxy_handler, char *timezone)
{
  connman_return_if_invalid_arg (connman_proxy_handler == NULL || timezone == NULL);

  net_connman_clock_call_set_property (connman_proxy_handler->clock_proxy, CONNMAN_PROP_TIMEZONE_STR, g_variant_new ("v", g_variant_new_string (timezone)), NULL, (GAsyncReadyCallback) s_connman_proxy_timezone_config_cb, connman_proxy_handler);
}

void
connman_proxy_clock_set_timezone_updates (connman_proxy_handler_t *connman_proxy_handler, char *timezone_updates)
{
  connman_return_if_invalid_arg (connman_proxy_handler == NULL || timezone_updates == NULL);

  net_connman_clock_call_set_property (connman_proxy_handler->clock_proxy, CONNMAN_PROP_TIMEZONEUPDATES_STR, g_variant_new ("v", g_variant_new_string (timezone_updates)), NULL, (GAsyncReadyCallback) s_connman_proxy_timezone_updates_config_cb, connman_proxy_handler);
}

int8_t
connman_proxy_clock_set_timeserver (connman_proxy_handler_t *connman_proxy_handler, char **ntps)
{
  int8_t ret = CONNMAN_PROXY_FAIL;
  GVariantBuilder *ntps_builder = NULL;
  GVariant *dict = NULL;
  connman_proxy_service_info_t *serv_obj = NULL;

  connman_return_val_if_invalid_arg (connman_proxy_handler == NULL || ntps == NULL, CONNMAN_PROXY_FAIL);

  CONNMAN_BUILD_GVAR_STRING_ARRAY (ntps_builder, ntps);
  dict = g_variant_builder_end (ntps_builder);
  net_connman_clock_call_set_property (connman_proxy_handler->clock_proxy, CONNMAN_PROP_TIMESERV_STR, g_variant_new ("v", dict), NULL, (GAsyncReadyCallback) s_connman_proxy_timeserver_config_cb, connman_proxy_handler);
  g_variant_builder_unref (ntps_builder);

  ret = CONNMAN_PROXY_SUCCESS;

safe_exit:
  return ret;
}
