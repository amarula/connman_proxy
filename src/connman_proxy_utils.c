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
 *  File             : connman_proxy_utils.c
 *  Description      : Utility functions like printing variant or service
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

#define MAX_DEPTH_LEVEL 10
char *s_depth_tab_str = "\t\t\t\t\t\t\t\t\t\t";

/**** Static ****/
/**** Hidden ****/

void
connman_proxy_util_print_array_of_string(GVariant *res)
{
    GVariantIter iter;
    gchar *value;

    g_variant_iter_init (&iter, res);
    while (g_variant_iter_next (&iter, "s", &value))
    {
        CONNMAN_LOG_USER("\t%s\n", value);
        g_free (value);
    }
}

void
connman_proxy_util_print_custom(GVariant *res)
{
    if(g_strcmp0(g_variant_get_type_string (res), "(sv)") == 0 )
    {
        GVariant *val = NULL;
        gchar *string = NULL;
        g_variant_get (res, "(sv)", &string, &val);
        connman_proxy_util_print_g_variant(string, val);
        g_free (string);
        g_variant_unref (val);
    }
    else
    {
        CONNMAN_LOG_WARNING("%-12s : Unknown Property of type '%s'\n", "test", g_variant_get_type_string (res));
    }
}

void
connman_proxy_util_print_array_of_dict(GVariant *res)
{
    GVariantIter iter;
    GVariant *value;
    gchar *key;

    g_variant_iter_init (&iter, res);
    while (g_variant_iter_next (&iter, "{sv}", &key, &value))
    {
        connman_proxy_util_print_g_variant(key, value);
        /*must free data for ourselves*/
        g_variant_unref (value);
        g_free (key);
    }
}

void
connman_proxy_g_free(gpointer data, gpointer user_data)
{
    CONNMAN_PROXY_UNUSED(user_data);
    g_free(data);
}

/**** Global ****/

CP_EXPORT void
connman_proxy_util_print_services(connman_proxy_service_info_t *service)
{
    CONNMAN_LOG_USER("\n************* Service %s *************\n", service->obj_path); 
    CONNMAN_LOG_USER( "\t\tService Name     : %s\n"
                      "\t\tName             : %s\n"
                      "\t\tType             : %s\n"
                      "\t\tSignale Strength : %hhu\n"
                      "\t\tState            : %s\n"
                      "\t\tFavourite        : %s\n"
                      "\t\tImmutable        : %s\n"
                      "\t\tAutoconnect      : %s\n"
                      "\t\tMDNS Enabled     : %s\n"
                      "\t\tIPV4\n"
                      "\t\t\tMethod         :%s\n"
                      "\t\t\tAddress        :%s\n"
                      "\t\t\tNetMask        :%s\n"
                      "\t\t\tGateWay        :%s\n"
                      "\t\tEthernet\n"
                      "\t\t\tMethod         :%s\n"
                      "\t\t\tInterface      :%s\n"
                      "\t\t\tMac Address    :%s\n"
                      "\t\t\tMTU            :%hu\n"
                      "\t\tNetwork Proxy\n"
                      "\t\t\tMethod         :%s\n"
                      "\t\t\tURL            :%s\n"
                      ,   
                        service->service_name, service->name ? service->name : "Hidden", service->type, service->signal_strength, service->state,
                        service->favorite ? "Yes": "No", service->immutable ? "Yes": "No", service->autoconnect ? "Yes": "No", service->mdns ? "Yes": "No",
                        service->ipv4.method, service->ipv4.address, service->ipv4.netmask, service->ipv4.gateway,
                        service->eth.method, service->eth.interface, service->eth.address, service->eth.mtu,
                        service->proxy.method, service->proxy.url ? service->proxy.url : "");

	/* To print PROXY/DNS/NTP/DOMAIN servers*/
	{   
		GSList  *tmp = NULL;
		int i = 0;
		for (i = 0, tmp = service->proxy.servers; tmp; tmp = g_slist_next (tmp), i++)
		{   
			CONNMAN_LOG_USER("\t\t\tPROXY %d - %s\n", i, (char *)tmp->data);
		}   
		CONNMAN_LOG_USER("\t\tExcludes\n");
		for (i = 0, tmp = service->proxy.exclude; tmp; tmp = g_slist_next (tmp), i++)
		{   
			CONNMAN_LOG_USER("\t\t\tEXCLUDE %d - %s\n", i, (char *)tmp->data);
		}   
		CONNMAN_LOG_USER("\t\tSecurity\n");
		for (i = 0, tmp = service->security; tmp; tmp = g_slist_next (tmp), i++)
		{   
			CONNMAN_LOG_USER("\t\t\tSecurity %d - %s\n", i, (char *)tmp->data);
		}   
		CONNMAN_LOG_USER("\t\tDNS\n");
		for (i = 0, tmp = service->nameservers; tmp; tmp = g_slist_next (tmp), i++)
		{
			CONNMAN_LOG_USER("\t\t\tDNS %d - %s\n", i, (char *)tmp->data);
		}
		CONNMAN_LOG_USER("\t\tTime Servers\n");
		for (i = 0, tmp = service->timeservers; tmp; tmp = g_slist_next (tmp), i++)
		{
			CONNMAN_LOG_USER("\t\t\tNTS %d - %s\n", i, (char *)tmp->data);
		}
		CONNMAN_LOG_USER("\t\tDomains\n");
		for (i = 0, tmp = service->domains; tmp; tmp = g_slist_next (tmp), i++)
		{
			CONNMAN_LOG_USER("\t\t\tDOMAIN %d - %s\n", i, (char *)tmp->data);
		}
		CONNMAN_LOG_USER("************* End *************\n");
	}
}

CP_EXPORT void
connman_proxy_util_print_g_variant(char *name, GVariant *val)
{
#if defined(CONNMAN_LOG_LEVEL) && (CONNMAN_LOG_LEVEL > CONN_LOG_INFO)
    static uint8_t depth_level = 0;
    if(depth_level > MAX_DEPTH_LEVEL)
    {
        CONNMAN_LOG_WARNING("Print MAX_DEPTH_LEVEL is %d and we have reached to depth %d.. \n", MAX_DEPTH_LEVEL, depth_level);
        return;
    }

    if(g_variant_type_equal(G_VARIANT_TYPE_BOOLEAN, g_variant_get_type(val)))
    {
        CONNMAN_LOG_USER ("%s%-12s : %s\n", s_depth_tab_str+(MAX_DEPTH_LEVEL-depth_level), name, g_variant_get_boolean (val) ? "Yes" : "No");
    }
    else if(g_variant_type_equal(G_VARIANT_TYPE_STRING, g_variant_get_type(val)))
    {
        CONNMAN_LOG_USER ("%s%-12s : %s\n", s_depth_tab_str+(MAX_DEPTH_LEVEL-depth_level), name, g_variant_get_string (val, NULL));
    }
    else if(g_variant_type_equal(G_VARIANT_TYPE_BYTE, g_variant_get_type(val)))
    {
        CONNMAN_LOG_USER ("%s%-12s : %"PRIu8"\n", s_depth_tab_str+(MAX_DEPTH_LEVEL-depth_level), name, g_variant_get_byte (val));
    }
    else if(g_variant_type_equal(G_VARIANT_TYPE_UINT16, g_variant_get_type(val)))
    {
        CONNMAN_LOG_USER ("%s%-12s : %"PRIu16"\n", s_depth_tab_str+(MAX_DEPTH_LEVEL-depth_level), name, g_variant_get_uint16 (val));
    }
    else if(g_variant_type_equal(G_VARIANT_TYPE_STRING_ARRAY, g_variant_get_type(val)))
    {
        CONNMAN_LOG_USER ("%s%s {\n", s_depth_tab_str+(MAX_DEPTH_LEVEL-depth_level), name);
        depth_level++;
        connman_proxy_util_print_array_of_string(val);
        depth_level--;
        CONNMAN_LOG_USER ("%s}\n", s_depth_tab_str+(MAX_DEPTH_LEVEL-depth_level));

    }
    else if(g_variant_type_equal(G_VARIANT_TYPE_VARDICT, g_variant_get_type(val)))
    {
        CONNMAN_LOG_USER ("%s%s {\n", s_depth_tab_str+(MAX_DEPTH_LEVEL-depth_level), name);
        depth_level++;
        connman_proxy_util_print_array_of_dict(val);
        depth_level--;
        CONNMAN_LOG_USER ("%s}\n", s_depth_tab_str+(MAX_DEPTH_LEVEL-depth_level));
    }
    else
    {
        connman_proxy_util_print_custom(val);
    }
#endif /* CONNMAN_LOG_LEVEL > CONN_LOG_ERROR */    
    return;
}
