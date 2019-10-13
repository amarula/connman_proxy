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
 *  File             : connman_proxy_test.c
 *  Description      : An example program to demonstrate the usage of all public API
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>

#include "connman_proxy.h"

#define CONNMAN_TEST_SELECT_SET(name, data, size) \
        {\
            int32_t i = 0, j = 0, total_set = 0;\
            total_set = sizeof(data) / (sizeof(char *) * size);\
            CONNMAN_LOG_USER("\nSelect %s Set From Below\n", name);\
            for( i = 0 ; i < total_set; i++)\
            {\
                CONNMAN_LOG_USER("%d -> Set %d [", i, i + 1);\
                for ( j = 0; data[i][j] != NULL ; j++)\
                {\
                    CONNMAN_LOG_USER(" %s ", data[i][j]);\
                }\
                CONNMAN_LOG_USER("]\n");\
            }\
            c = s_connman_get_single_key();\
            if(c < '0' || (c - '0') >= total_set)\
                break;\
        }

static pthread_t s_kbd_event_thread;
static volatile gboolean s_event_run = TRUE;

void connman_init_keyboard_input(connman_proxy_handler_t *connman_proxy_handler);
void connman_reset_keyboard_input();
gboolean connman_key_is_pressed(int32_t *character);

static void s_connman_proxy_get_current_state(connman_proxy_handler_t *connman_proxy_handler);
static void s_connman_proxy_get_technologies(connman_proxy_handler_t *connman_proxy_handler);
static void s_connman_proxy_get_services(connman_proxy_handler_t *connman_proxy_handler);
static int32_t s_connman_get_single_key(void);
void* connman_on_key_pressed(void *user_data);

gboolean connman_proxy_test_update_cb(connman_proxy_update_cb_data_t *notification_data, gpointer cookie);
gboolean connman_proxy_test_input_cb(connman_mgr_request_input_type_t input_type);

/****** Test Inputs (NULL terminated)********/
char *tmp_ip4[][5] = {
						{"manual", "192.168.100.10", "255.255.255.0", "192.168.100.1", NULL},
						{"manual", "192.168.100.10",  NULL, NULL, NULL},
						{"manual", "192.168.100.10", "255.255.255.0", NULL, NULL},
						{"off", NULL, NULL, NULL, NULL},
						{"dhcp", NULL, NULL, NULL, NULL}
					};
char *tmp_proxy_method[] = { "manual", "auto", "direct", NULL };
char *tmp_servers[] = {"www.proxy1.com:3128", "www.proxy2.com:3128", "www.proxy3.com:3128", NULL, NULL };
char *tmp_proxy_url = "http://192.168.1.10/proxy.url";
char *tmp_excludes[] = {"www.gmail.com", "www.twitter.com", NULL};
char *tmp_dns[][4] = {
			  			{"8.8.8.8", "4.4.4.4", "2.2.2.2", NULL},
	  					{"8.8.8.8", "6.6.6.6", "4.4.4.4", NULL}
  					};
char *tmp_domains[][4] = {
							{"google.com", "oneplus.com", "yahoo.com", NULL},
							{"amazon.com", "apple.com", "oneplus.com", NULL}
						};
char *tmp_ntps[][4] =  {
							{"in.pool.ntp.org", "asia.pool.ntp.org", "asia.pool.ntp.org", NULL},
							{"asia.pool.ntp.org", "in.pool.ntp.org", "asia.pool.ntp.org", NULL}
						};

connman_proxy_callback_handlers_t g_cb_handlers =
{
    connman_proxy_test_update_cb,   /*on_update_cb*/
    connman_proxy_test_input_cb,    /*on_input_request*/
    NULL                            /*Cookie*/
};

static void
s_print_usage()
{
    CONNMAN_LOG_USER("=============================\n"
                "1. Get State\n"
                "2. Get Technologies\n"
                "3. Get Service\n"
                "4. Print Service\n"
                "5. Configure DNS\n"
                "6. Configure Time Servers\n"
                "7. Configure Domains\n"
                "8. Toggle AutoConnect\n"
                "9. Configure Ip4\n"
                "p. Configure Proxy\n"
                "o. Offline Mode\n"
                "r. Power\n"
                "s. Scan\n"
                "n. Connect\n"
                "d. DisConnect\n"
                "f. Forget/Remove Service\n"
                "h. Help ( Or Press Space to Print this menu )\n"
                "e. Exit ( Or Press Esc)\n"
                "=============================\n"
                );
    return;
}

static void
s_connman_proxy_get_current_state(connman_proxy_handler_t *connman_proxy_handler)
{
    if(connman_proxy_handler == NULL)
    {
        CONNMAN_LOG_ERROR("Invalid Connman Poxy Handler\n");
        goto safe_exit;
    }
    CONNMAN_LOG_USER( "********** Current Network State **********\n");
    CONNMAN_LOG_USER( "\tGlobal State  : %s\n"
                "\tOffline Mode  : %s\n"
                "\tTechnologies  : %u\n"
                "\tServices      : %u\n"
                "******************* End *******************\n",
                connman_proxy_handler->global_state, connman_proxy_handler->offline_mode ? "Yes": "No",
                (connman_proxy_handler->technologies) ? g_slist_length(connman_proxy_handler->technologies) : 0,
                (connman_proxy_handler->services) ? g_hash_table_size(connman_proxy_handler->services) : 0);
safe_exit:
    return;
}

static void
s_connman_proxy_get_services(connman_proxy_handler_t *connman_proxy_handler)
{
    uint8_t i = 0;
    GHashTableIter iter;
    gpointer key, value;
    connman_proxy_service_info_t *service = NULL;
    
    if(connman_proxy_handler == NULL)
    {
        CONNMAN_LOG_ERROR("Invalid Connman Poxy Handler\n");
        goto safe_exit;
    }
    if(connman_proxy_handler->services == NULL || g_hash_table_size(connman_proxy_handler->services) == 0)
    {
        CONNMAN_LOG_WARNING("No services available !!!\n");
        goto safe_exit;
    }

    g_hash_table_iter_init (&iter, connman_proxy_handler->services);
    while (g_hash_table_iter_next (&iter, &key, &value))
    {
        service = (connman_proxy_service_info_t *)value;
        CONNMAN_LOG_USER("\t***** Service %d *****\n", i++); 
        CONNMAN_LOG_USER( "\t\tObject Path  : %s\n"
                          "\t\tName         : [%s] %s\n"
                          "\t\tType         : %s\n",
                    (gchar *)key, service->name ? service->name : "**Hidden**", service->service_name, service->type);
    }
safe_exit:
    return;
}

static void
s_connman_proxy_get_technologies(connman_proxy_handler_t *connman_proxy_handler)
{
    uint8_t i = 0;
    GSList  *tmp_node = NULL;
    connman_proxy_technology_info_t *tmp_tech = NULL;
    
	if(connman_proxy_handler == NULL)
    {
        CONNMAN_LOG_ERROR("Invalid Connman Poxy Handler\n");
        goto safe_exit;
    }
    if(connman_proxy_handler->technologies == NULL || g_slist_length(connman_proxy_handler->technologies) == 0)
    {
        CONNMAN_LOG_WARNING("No Technology available !!!\n");
        goto safe_exit;
    }

    for (i = 0, tmp_node = connman_proxy_handler->technologies; tmp_node; tmp_node = g_slist_next (tmp_node), i++)
    {   
        tmp_tech = tmp_node->data;
        CONNMAN_LOG_USER("\t***** Techology %d *****\n", i); 
        CONNMAN_LOG_USER( "\t\tObject Path  : %s\n"
                          "\t\tName         : %s\n"
                          "\t\tType         : %s\n"
                          "\t\tPowered      : %s\n"
                          "\t\tConnected    : %s\n"
                          "\t\tTethered     : %s\n",
                    tmp_tech->obj_path, tmp_tech->name, tmp_tech->type,
                    tmp_tech->powered?"Yes" : "No", tmp_tech->connected?"Yes" : "No", tmp_tech->tethering?"Yes" : "No");
    }   
safe_exit:
    return;
}

/* gmain loop*/
static gpointer
s_connman_run_loop(gpointer user_data)
{
    connman_proxy_handler_t *connman_proxy_handler = (connman_proxy_handler_t *)user_data;

    g_main_loop_run (connman_proxy_handler->loop); /* Blocked until g_main_quit is called*/
    return NULL;
}

int32_t
s_connman_get_single_key()
{
    int32_t key = 'h';
    while (s_event_run)
    {
        if (connman_key_is_pressed(&key))
        {
            key = tolower(key);
            break;
        }
        else
            usleep(100);
    }

    return key;
}

static connman_proxy_technology_info_t *
s_select_tech_from_list(connman_proxy_handler_t *connman_proxy_handler)
{
    int8_t i = 0;
    int32_t c = 0;
    GSList  *tmp_node = NULL;
    connman_proxy_technology_info_t *tmp_tech = NULL;

    CONNMAN_LOG_USER("\nSelect A Technology From Below\n");
    for (i = 0, tmp_node = connman_proxy_handler->technologies; tmp_node; tmp_node = g_slist_next (tmp_node), i++)
    {
        tmp_tech = tmp_node->data;
        CONNMAN_LOG_USER("\t\t%d -> %s\n", i, tmp_tech->type);
    }
    c = s_connman_get_single_key();
    if(c >= '0' && (c - '0') < g_slist_length(connman_proxy_handler->technologies))
        tmp_tech = g_slist_nth_data(connman_proxy_handler->technologies, (guint)(c - '0'));
    else
        tmp_tech = NULL;

    return tmp_tech;
}

static connman_proxy_service_info_t *
s_select_service_from_list(connman_proxy_handler_t *connman_proxy_handler)
{
    uint8_t i = 0;
    int32_t c = 0;

    GHashTableIter iter;
    gpointer key, value;
    connman_proxy_service_info_t **tmp_srv_list = NULL;
    connman_proxy_service_info_t *ret_srv = NULL;

    if(connman_proxy_handler->services == NULL)
    {
        CONNMAN_LOG_WARNING("No services available yet!!!\n");
        return ret_srv;
    }
    tmp_srv_list =  malloc(g_hash_table_size(connman_proxy_handler->services) * sizeof(connman_proxy_service_info_t*));

    CONNMAN_LOG_USER("\nSelect A Service From Below\n");
    g_hash_table_iter_init (&iter, connman_proxy_handler->services);
    while (g_hash_table_iter_next (&iter, &key, &value))
    {
        CONNMAN_LOG_USER("\t\t%d -> [%s] %s\n", i, ((connman_proxy_service_info_t *)value)->name ? ((connman_proxy_service_info_t *)value)->name : "*Hidden*", ((connman_proxy_service_info_t *)value)->service_name);
        tmp_srv_list[i] = (connman_proxy_service_info_t *)value;
		i++;
    }
    c = s_connman_get_single_key();

    if(c >= '0' && (c - '0') < g_hash_table_size(connman_proxy_handler->services))
        ret_srv = tmp_srv_list[(guint)(c - '0')];
    else
        ret_srv = NULL;
    free(tmp_srv_list);
    return ret_srv;
}

gboolean connman_proxy_test_input_cb(connman_mgr_request_input_type_t input_type)
{
    char identity[CONNMAN_MGR_AGENT_MAX_INPUT_LENGTH], passphrase[CONNMAN_MGR_AGENT_MAX_INPUT_LENGTH];
    GVariantBuilder * input_builder = NULL;
    GVariant *_value = NULL, *res = NULL;

    gboolean ret = TRUE;

    switch(input_type)
    {
        case CONNMAN_MGR_INPUT_TYPE_PASSPHRASE:
        {
            CONNMAN_LOG_USER("%s: Enter Password [Enter cancel to cancel the request]: ", " WiFi Service");
            fflush(stdout);
            scanf("%s", passphrase);

            if(0 == strcmp(passphrase, "cancel")) /* For testing cancel API*/
                connman_mgr_cancel_user_input(input_type);
            else
            {
                input_builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
                _value = g_variant_new("s", passphrase);
                g_variant_builder_add (input_builder, "{sv}", "Passphrase", _value);
                res = g_variant_new("a{sv}", input_builder);
                if(FALSE == connman_mgr_set_user_input(input_type, res))
                    g_variant_unref (res);
                g_variant_builder_unref (input_builder);
            }
            break;
        }
        default:
            CONNMAN_LOG_WARNING("!!!!!!!!!! Input Type %d Not Handled !!!!!!!!!!\n", input_type);
            CONNMAN_PROXY_UNUSED(identity);
            ret = FALSE;
            break;
    }
    return ret;
}

gboolean connman_proxy_test_update_cb(connman_proxy_update_cb_data_t *notification_data, gpointer cookie)
{
    gboolean ret = TRUE;
    if(NULL == notification_data)
        return FALSE;
    switch(notification_data->notify_type)
    {
        case CONNMAN_PROXY_NOTIFY_CONNMAN_SERVICE_UPDATE:
            CONNMAN_LOG_INFO("Connman Service is %s now\n", notification_data->data.service_available ? "Available" : "Unavailable");
            break;
        case CONNMAN_PROXY_NOTIFY_ERROR:
            CONNMAN_LOG_ERROR("Error Code : %d\n", notification_data->data.error_code );
            break;
        case CONNMAN_PROXY_NOTIFY_OFFLINE_UPDATE:
            CONNMAN_LOG_INFO("Offline Mode %s\n", notification_data->data.offline_enabled ? "Enabled" : "Disabled");
            break;
        case CONNMAN_PROXY_NOTIFY_GLOBAL_STATE:
            CONNMAN_LOG_INFO("Global state Updated : %s\n", notification_data->data.global_state);
            break;
        case CONNMAN_PROXY_NOTIFY_SERVICE_UPDATE:
            CONNMAN_LOG_INFO("Interface [%s] Service [%s] Updated : [%s] [%s] [%hhu %%]\n",
                            notification_data->data.serv.interface, (notification_data->data.serv.name) ?notification_data->data.serv.name : "-",
                            notification_data->data.serv.state, notification_data->data.serv.type, notification_data->data.serv.signal_strength);
            if(notification_data->data.serv.name)
                g_free(notification_data->data.serv.name);
            break;
        case CONNMAN_PROXY_NOTIFY_TECH_UPDATE:
            CONNMAN_LOG_INFO("[%s] Updated : \[%spowered ] [ %sconnected ]\n",
                            notification_data->data.tech.type ? notification_data->data.tech.type : "Unknown",
                            notification_data->data.tech.powered ? " ": " Not ", notification_data->data.tech.connected ? " ": " Not ");
            if(notification_data->data.tech.type)
                g_free(notification_data->data.tech.type );
            break;
        case CONNMAN_PROXY_NOTIFY_SCAN_COMPLETED:
            CONNMAN_LOG_INFO("WiFi Scan Completed\n");
            break;
        default:
            CONNMAN_LOG_WARNING("!!!!!!!!!! Noification %d Not Handled !!!!!!!!!!\n", notification_data->notify_type);
            ret = FALSE;
            break;
    }
    free(notification_data);
    return ret;
}

void * connman_on_key_pressed(void *user_data)
{
    int32_t c = 0;
	connman_proxy_handler_t *connman_proxy_handler =  (connman_proxy_handler_t *)user_data;
    connman_proxy_technology_info_t *tmp_tech = NULL;
    connman_proxy_service_info_t *tmp_srv = NULL;

    while (s_event_run)
    {
        if (connman_key_is_pressed(&c))
        {
            c = tolower(c);
            switch (c)
            {
                case '1':
                    s_connman_proxy_get_current_state(connman_proxy_handler);
                    break;
                case '2':
					s_connman_proxy_get_technologies(connman_proxy_handler);
                    break;
                case '3':
					s_connman_proxy_get_services(connman_proxy_handler);
                    break;
                case '4':
                    tmp_srv = s_select_service_from_list(connman_proxy_handler);
                    if(tmp_srv)
						connman_proxy_util_print_services(tmp_srv);
                    break;
                case '5':
                    tmp_srv = s_select_service_from_list(connman_proxy_handler);
                    if(tmp_srv)
                    {
                        CONNMAN_TEST_SELECT_SET("DNS", tmp_dns, 4);
						if(connman_proxy_configure_nameserver(connman_proxy_handler, tmp_srv->obj_path, &tmp_dns[c - '0'][0]) != 0)
                        {
                            CONNMAN_LOG_ERROR("Invalid argument\n");
                        }
                    }   
                    break;
                case '6':
                    tmp_srv = s_select_service_from_list(connman_proxy_handler);
                    if(tmp_srv)
                    {
                        CONNMAN_TEST_SELECT_SET("NTPS", tmp_ntps, 4);
						if(connman_proxy_configure_timeserver(connman_proxy_handler, tmp_srv->obj_path, &tmp_ntps[c - '0'][0]) != 0)
                        {
                            CONNMAN_LOG_ERROR("Invalid argument\n");
                        }
                    }
                    break;
                case '7':
                    tmp_srv = s_select_service_from_list(connman_proxy_handler);
                    if(tmp_srv)
                    {   
                        CONNMAN_TEST_SELECT_SET("Domain", tmp_domains, 4);
						if(connman_proxy_configure_domain(connman_proxy_handler, tmp_srv->obj_path, &tmp_domains[c - '0'][0]) != 0)
                        {
                            CONNMAN_LOG_ERROR("Invalid argument\n");
                        }
                    }
                    break;
                case '8':
                    tmp_srv = s_select_service_from_list(connman_proxy_handler);
                    if(tmp_srv)
                    {
                        gboolean autoconnect = FALSE;
                        CONNMAN_LOG_USER("\n\n"
                            "\t0 -> Autoconnect Off\n"
                            "\t1 -> Autoconnect On\n"
                        );
                        c = s_connman_get_single_key();
                        autoconnect = (c - '0') ? TRUE : FALSE;
                        connman_proxy_set_service_autoconnect(connman_proxy_handler, tmp_srv->obj_path, autoconnect);
                    }
                    break;
                case '9':
                    tmp_srv = s_select_service_from_list(connman_proxy_handler);
                    if(tmp_srv)
                    {   
                        CONNMAN_TEST_SELECT_SET("Ip4 Configuration", tmp_ip4, 5);
						if(connman_proxy_configure_ipv4(connman_proxy_handler, tmp_srv->obj_path, tmp_ip4[c - '0'][0], tmp_ip4[c - '0'][1], tmp_ip4[c - '0'][2], tmp_ip4[c - '0'][3]) != 0)
                        {
                            CONNMAN_LOG_ERROR("Invalid argument\n");
                        }
                    }
                    break;
                case 'o':
                {
                    gboolean enable = FALSE;
                    CONNMAN_LOG_USER("\n\n"
                        "\t0 -> Turn Off Offline Mode\n"
                        "\t1 -> Turn On Offline Mode\n"
                    );
                    c = s_connman_get_single_key();
                    enable = (c - '0') ? TRUE : FALSE;
                    connman_proxy_set_offline(connman_proxy_handler, enable);
                    break;
                }
                case 'p':
                    tmp_srv = s_select_service_from_list(connman_proxy_handler);
                    if(tmp_srv)
                    { 
                        CONNMAN_LOG_USER("\nSelect Proxy Configuration Set From Below\n"
                        "0 -> Set 1 [manual, www.proxy1.com:3128, www.proxy2.com:3128, www.proxy3.com:3128 - Exclude www.gmail.com, www.oneplus.com]\n"
                        "1 -> Set 2 [auto, http://192.168.1.10/proxy.url]\n"
                        "2 -> Set 3 [direct]\n"
                        );  
						c = s_connman_get_single_key();
                        if(connman_proxy_configure_proxy(connman_proxy_handler, tmp_srv->obj_path, tmp_proxy_method[c - '0'], tmp_proxy_url, &tmp_servers[0], &tmp_excludes[0]) != 0)
                        {
                            CONNMAN_LOG_ERROR("Invalid argument\n");
                        }
                    }
                    break;
                case 's':
                    tmp_tech = s_select_tech_from_list(connman_proxy_handler);
                    if(tmp_tech)
                        connman_proxy_scan_technology(connman_proxy_handler, tmp_tech->obj_path);
                    break;
                case 'r':
                    tmp_tech = s_select_tech_from_list(connman_proxy_handler);
                    if(tmp_tech)
                    {
                        gboolean powered = FALSE;
                        CONNMAN_LOG_USER("\n\n"
                            "\t0 -> Power Off\n"
                            "\t1 -> Power On\n"
                        );
                        c = s_connman_get_single_key();
                        powered = (c - '0') ? TRUE : FALSE;
                        connman_proxy_set_technology_power(connman_proxy_handler, tmp_tech->obj_path, powered);
                    }
                    break;
                case 'n':
                    tmp_srv = s_select_service_from_list(connman_proxy_handler);
                    if(tmp_srv)
                        connman_proxy_connect_service(connman_proxy_handler, tmp_srv->obj_path);
                    break;
                case 'd':
                    tmp_srv = s_select_service_from_list(connman_proxy_handler);
                    if(tmp_srv)
                        connman_proxy_disconnect_service(connman_proxy_handler, tmp_srv->obj_path);
                    break;
                case 'f':
                    tmp_srv = s_select_service_from_list(connman_proxy_handler);
                    if(tmp_srv)
                        connman_proxy_remove_service(connman_proxy_handler, tmp_srv->obj_path);
                    break;
                case 27:
                case 'e':
                    s_event_run = FALSE;
                    g_main_quit(connman_proxy_handler->loop);
                    break;
                case 'h':
                default:
                    s_print_usage();
                    break;
            } /* switch*/
        }/*key_pressed*/
        else
            usleep(100);
    }/*while*/
    
    return NULL;
}

int main(int argc,char *argv[])
{
    connman_proxy_handler_t *connman_proxy_handler = NULL;

    connman_proxy_handler = connman_proxy_init(&g_cb_handlers, NULL);
    if(connman_proxy_handler == NULL)
    {
        CONNMAN_LOG_ERROR("xxxxxxxxxx Connman Proxy Init failed xxxxxxxxxx\n");
        return -1;
    }
    CONNMAN_PROXY_UNUSED(argc);
    CONNMAN_PROXY_UNUSED(argv);

    connman_init_keyboard_input(connman_proxy_handler);
    pthread_create(&s_kbd_event_thread, NULL, connman_on_key_pressed, connman_proxy_handler);

    s_print_usage();
    s_connman_run_loop(connman_proxy_handler);

    /* Do clean-ups here */
    if(s_event_run == TRUE)
        s_event_run = FALSE;
    
    pthread_join(s_kbd_event_thread, NULL);

    connman_reset_keyboard_input();

    connman_proxy_deinit(connman_proxy_handler);

    return 0;
}
