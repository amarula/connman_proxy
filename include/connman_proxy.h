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
 *  File             : connman_proxy.h
 *  Description      : All the public interface, macros, structures and enums are defined here.
 *
 */

#ifndef __CONNMAN_PROXY_H
#define __CONNMAN_PROXY_H

#include <inttypes.h>
#include <gio/gio.h>

#define  CONN_LOG_FATAL 1 /**< Only Fatal errors will be printed.*/
#define  CONN_LOG_ERROR 2 /**< Only Errors will be printed including the Fatal error*/
#define  CONN_LOG_WARN  3 /**< Warnings and all the errors will be printed.*/
#define  CONN_LOG_INFO  4 /**< Improtannt Info logs, Warnings and all the errors will be printed.*/
#define  CONN_LOG_DEBUG 5 /**< Debug logs, Improtannt Info logs, Warnings and all the errors will be printed.*/
#define  CONN_LOG_TRACE 6 /**< All the logs will be printed */

/**
 * Default Log level CONN_LOG_INFO
 */
#ifndef CONNMAN_LOG_LEVEL
#define CONNMAN_LOG_LEVEL CONN_LOG_INFO
#endif

/* Logging Macro */
#if defined(CONNMAN_LOG_LEVEL) && (CONNMAN_LOG_LEVEL >= CONN_LOG_FATAL)
    #define CONNMAN_LOG_FATAL(msg,args...) \
		printf("\e[0;31m%-9s : %s -> %s(%d) : " msg "\e[0m", "[FATAL]", __FILE__, __func__, __LINE__, ## args);
#else
    #define CONNMAN_LOG_FATAL(msg,args...) 
#endif

#if defined(CONNMAN_LOG_LEVEL) && (CONNMAN_LOG_LEVEL >= CONN_LOG_ERROR)
    #define CONNMAN_LOG_ERROR(msg,args...) \
		printf("\e[0;31m%-9s : %s -> %s(%d) : " msg "\e[0m", "[ERROR]", __FILE__, __func__, __LINE__, ## args);
#else
    #define CONNMAN_LOG_ERROR(msg,args...) 
#endif

#if defined(CONNMAN_LOG_LEVEL) && (CONNMAN_LOG_LEVEL >= CONN_LOG_WARN)
    #define CONNMAN_LOG_WARNING(msg,args...) \
		printf("\e[0;33m%-9s : %s -> %s(%d) : " msg "\e[0m", "[WARNING]", __FILE__, __func__, __LINE__, ## args);
#else
    #define CONNMAN_LOG_WARNING(msg,args...) 
#endif

#if defined(CONNMAN_LOG_LEVEL) && (CONNMAN_LOG_LEVEL >= CONN_LOG_INFO)
    #define CONNMAN_LOG_INFO(msg,args...) \
		printf("\e[0;32m%-9s :\e[0m %s -> %s(%d) : " msg, "[INFO]", __FILE__, __func__, __LINE__, ## args);
#else
    #define CONNMAN_LOG_INFO(msg,args...)
#endif

#if defined(CONNMAN_LOG_LEVEL) && (CONNMAN_LOG_LEVEL >= CONN_LOG_DEBUG)
    #define CONNMAN_LOG_DEBUG(msg,args...) printf("\e[0;36m%-9s :\e[0m %s -> %s(%d) : " msg, "[DEBUG]", __FILE__, __func__, __LINE__, ## args);
#else
    #define CONNMAN_LOG_DEBUG(msg,args...)
#endif

#if defined(CONNMAN_LOG_LEVEL) && (CONNMAN_LOG_LEVEL >= CONN_LOG_TRACE)
    #define CONNMAN_LOG_TRACE(msg,args...) printf("\e[0;34m%-9s :\e[0m %s -> %s(%d) : " msg, "[TRACE]", __FILE__, __func__, __LINE__, ## args);
    #define CONNMAN_UTIL_PRINT_G_VARIENT(obj_path, properties) connman_proxy_util_print_g_variant(obj_path, properties)
    #define CONNMAN_UTIL_PRINT_DICT_ARR(params) connman_proxy_util_print_array_of_dict(params);
#else
    #define CONNMAN_LOG_TRACE(msg,args...) 
    #define CONNMAN_UTIL_PRINT_G_VARIENT(obj_path, properties)
    #define CONNMAN_UTIL_PRINT_DICT_ARR(params)
#endif

/* User custom prints for developers for extra debugging */
#define CONNMAN_LOG_USER(msg, args...) \
	printf(msg, ## args);

/**
 * Used for removing unused variables compiler warnings
 */
#define CONNMAN_PROXY_UNUSED(arg) (void)arg

/**
 * Enum for the return status
 */
typedef enum
{
    CONNMAN_PROXY_FAIL = -1,  /**< -1*/
    CONNMAN_PROXY_SUCCESS = 0 /**< 0*/
}connman_proxy_status_t;

/**
 * Enum for the notification data types
 */
typedef enum
{
    CONNMAN_PROXY_NOTIFY_GLOBAL_STATE = 0, /**< 0*/
    CONNMAN_PROXY_NOTIFY_SERVICE_UPDATE, /**< 1*/
    CONNMAN_PROXY_NOTIFY_TECH_UPDATE, /**< 2*/
    CONNMAN_PROXY_NOTIFY_OFFLINE_UPDATE, /**< 3*/
    CONNMAN_PROXY_NOTIFY_SCAN_COMPLETED, /**< 4*/
    CONNMAN_PROXY_NOTIFY_CONNMAN_SERVICE_UPDATE, /**< 5*/
    CONNMAN_PROXY_NOTIFY_ERROR, /**< 6*/
    CONNMAN_PROXY_NOTIFY_ENDEF  /**< Invalid notification type*/
}connman_proxy_notify_type_t;

/**
 * Enum for connman error notifications
 */
typedef enum
{
    CONNMAN_PROXY_CONFIG_OFFLINE_MODE_ERROR = 0,    /**<  0 Failed to configure offline mode */
    CONNMAN_PROXY_SCAN_ERROR,                       /**<  1 Failed to scan Wifi network */
    CONNMAN_PROXY_CONFIG_POWER_ERROR,               /**<  2 Failed to configure power of a tech */
    CONNMAN_PROXY_SERVICE_CONNECT_ERROR,            /**<  3 Failed to connect to requested service */
    CONNMAN_PROXY_SERVICE_DISCONNECT_ERROR,         /**<  4 Failed to disconnect to requested service */
    CONNMAN_PROXY_SERVICE_REMOVE_ERROR,             /**<  5 Failed to remove/forget of a service*/
    CONNMAN_PROXY_CONFIG_AUTOCONNECT_ERROR,         /**<  6 Failed to configure autoconnect property of a service*/
    CONNMAN_PROXY_CONFIG_MDNS_ERROR,                /**<  7 Failed to configure mdns property of a service*/
    CONNMAN_PROXY_CONFIG_IPV4_ERROR,                /**<  8 Failed to configure IPV4 settings of a service*/
    CONNMAN_PROXY_CONFIG_PROXY_ERROR,               /**<  9 Failed to configure Proxy settings of a service*/
    CONNMAN_PROXY_CONFIG_DNS_ERROR,                 /**< 10 Failed to configure DNS settings of a service*/
    CONNMAN_PROXY_CONFIG_NTPS_ERROR,                /**< 11 Failed to configure NTP server for a service*/
    CONNMAN_PROXY_CONFIG_DOMAIN_ERROR,              /**< 12 Failed to configure Domain settings of a service*/
    CONNMAN_PROXY_INVALID_KEY_ERROR,                /**< 13 Invalid Wifi Key Entered*/
    CONNMAN_PROXY_UNKNOWN_ERROR,                    /**< 14 Unknown Error */
}connman_proxy_error_type_t;

/*Connman manager Enum*/
typedef enum
{
    CONNMAN_MGR_INPUT_TYPE_SSID = 0,
    CONNMAN_MGR_INPUT_TYPE_IDENTITY,
    CONNMAN_MGR_INPUT_TYPE_PASSPHRASE,
    CONNMAN_MGR_INPUT_TYPE_WPS,
    CONNMAN_MGR_INPUT_TYPE_WISPR_USERNAME,
    CONNMAN_MGR_INPUT_TYPE_WISPR_PASSPHRASE,
    CONNMAN_MGR_INPUT_TYPE_ENDDEF
}connman_mgr_request_input_type_t;

/**
 * Structure to store update notification information for technology
 */
typedef struct
{
    gchar *type;                /**< Type of this Technlogy interface (ethernet, wifi etc) */
    gboolean powered;           /**< Whether this Technlogy powered on*/
    gboolean connected;         /**< Whether this Technlogy connected */
    gboolean tethered;          /**< Whether this Technlogy tethered. (Tethering is not supported yet)*/
}connman_proxy_notify_tech_update_data_t;

/**
 * Structure to store update notification information for service
 */
typedef struct
{
    char        *name;              /**< SSID for Wifi */
    char        interface[16];      /**< Interface name, eth0, wln0 etc*/
    char        type[16];           /**< Type of the network interface ("ethernet", "wifi" etc)*/
    char        state[16];          /**< Current state of this network interface ("idle", "failure", "association", "configuration", "ready", "disconnect" and "online")*/
    uint8_t     signal_strength;    /**< Wifi Signal strength. Not applicable for ethernet*/
}connman_proxy_notify_serv_update_data_t;

/**
 * Structure to store all notification callback data
 */
typedef struct
{
    connman_proxy_notify_type_t notify_type;
    union
    {
        gboolean service_available; /**< Tells if the network service is available or not*/
        char  global_state [8];     /**< Data for CONNMAN_PROXY_NOTIFY_GLOBAL_STATE notification which contains network state of the system */
        char  service_state [8];    /**< Data for CONNMAN_PROXY_NOTIFY_SERVICE_STATE notification which contains network state of the system */
        gboolean tech_connected;    /**< Data for CONNMAN_PROXY_NOTIFY_TECH_STATE tells if a tehcnology is connected or disconnected */
        gboolean offline_enabled;   /**< Data for CONNMAN_PROXY_NOTIFY_OFFLINE_MODE tells if the offline mode is enabled or disabled*/
        connman_proxy_error_type_t error_code;          /**< Data for CONNMAN_PROXY_NOTIFY_ERROR notification contains error code.*/
        connman_proxy_notify_tech_update_data_t tech;   /**< Data for CONNMAN_PROXY_NOTIFY_TECH_UPDATE notification containing tech infomration*/
        connman_proxy_notify_serv_update_data_t serv;   /**< Data for CONNMAN_PROXY_NOTIFY_SERVICE_UPDATE notification containing service infomration*/
    }data;
}connman_proxy_update_cb_data_t;

/**
* Typedef for data types and function pointers
*/

typedef gboolean (*connman_proxy_on_update_cb_t)(connman_proxy_update_cb_data_t *update_data, gpointer cookie); /**< Callback function to notify the clinet about network updates with data connman_proxy_update_cb_data_t*/
typedef gboolean (*connman_proxy_on_input_req_cb_t)(connman_mgr_request_input_type_t input_type); /**< Callback function to notify the clinet when there is a input of type connman_mgr_request_input_type_t required */

/**
 * Structure to store ethrnet information like method, interface name, mac address and MTU
 */
typedef struct
{
    char method[8];     /**< Ethernet configuration ("auto" and "manual")*/
    char interface[16]; /**< Interface name, eth0, wln0 etc*/
    char address[24];   /**< MAC address of theinterface*/
    uint16_t mtu;       /**< The Ethernet MTU */
}connman_proxy_eth_info_t;

/**
 * Structure to store IPv4 Information of a perticular interface
 */
typedef struct
{
    char method[8];     /**< Connection Method: ("dhcp", "manual", auto and "off") */
    char address[16];   /**< Ipv4 Address */
    char netmask[16];   /**< NetMask of the IPv4 iterface*/
    char gateway[16];   /**< GateWay of the IPv4 iterface*/
}connman_proxy_ipv4_info_t;

/**
 * Structure to store IPv6 Information of a perticular interface
 */
typedef struct
{
    char method[8];         /**< Connection Method: ("dhcp", "manual", "6to4" and "off")*/
    char address[64];       /**< Ipv6 Address */
    uint8_t prefix_length;  /**< Length of the prefix */
    char gateway[16];       /**< GateWay of the IPv6 iterface*/
    char privacy[16];       /**< Privacy type ("auto", "disabled", "enabled" and "prefered")*/
}connman_proxy_ipv6_info_t;

/**
 * Structure to store proxy Information of a perticular interface
 */
typedef struct
{
    char method[8];     /**< Method/Type of proxy  ("direct", "auto" and "manual")*/
    char *url;          /**< Automatic proxy configuration URL, used when method is auto, ignored when direct*/
    GSList *servers;    /**< List of proxy servers like server.example.com:911. Used when method is manual, ignored when direct or auto*/
    GSList *exclude;    /**< List of hosts which can be accessed directly. Used when method is manual, ignored when direct or auto*/
}connman_proxy_proxy_info_t;

/**
 * Structure object to store Information of a perticular service
 */
typedef struct
{
    gpointer    srv_proxy;   /**< Proxy object of the Connman Service interface*/
    char        *obj_path;          /**< Object path of this service interface */
    char        *service_name;      /**< Name of the interface*/
    char        *name;              /**< SSID for Wifi */
    char        type[16];           /**< Type of the network interface ("ethernet", "wifi" etc)*/
    uint8_t     signal_strength;    /**< Wifi Signal strength. Not applicable for ethernet*/
    char        state[16];          /**< Current state of this network interface ("idle", "failure", "association", "configuration", "ready", "disconnect" and "online")*/
    char        error[24];          /**< Stores the error message durig the error ("out-of-range", "pin-missing", "dhcp-failed", "connect-failed", "login-failed", "auth-failed" and "invalid-key")*/
    gboolean    favorite;           /**< True if ethernet cable is plugged or the user selected and succesfully connected to this network*/
    gboolean    immutable;          /**< This value will be set to true if the service is configured externally via a configuration file.*/
    gboolean    autoconnect;        /**< If set to true, this service will auto-connect when no other connection is available*/
    gboolean    mdns;               /**< Whether or not mDNS support is enabled*/
    GSList *nameservers;            /**< The list of DNS*/
    GSList *timeservers;            /**< The list of Time servers*/
    GSList *domains;                /**< The list of currently used search domains */
    GSList *security;               /**< The list of security methods or key management settings for WiFi only ( "none", "wep", "psk", "ieee8021x" "wps" )*/
    connman_proxy_proxy_info_t proxy;   /**< Proxy information */
    connman_proxy_eth_info_t eth;       /**< Ethernet interface information */
    connman_proxy_ipv4_info_t ipv4;     /**< IPv4 information */
    connman_proxy_ipv6_info_t ipv6;     /**< IPv6 information */
    /*dict Provider (VPN)*/
}connman_proxy_service_info_t;

/**
 * Structure object to store Information of a perticular technology
 */
typedef struct
{
    gpointer tech_proxy;                /**< Proxy object of the connman Technlogy interface*/
    gchar *obj_path;                    /**< Object path of this Technlogy interface**/
    gchar *name;                        /**< Name of this Technlogy interface*/
    gchar *type;                        /**< Type of this Technlogy interface (ethernet, wifi etc) */
    gboolean powered;                   /**< Whether this Technlogy powered on*/
    gboolean connected;                 /**< Whether this Technlogy connected */
    gboolean tethering;                 /**< Whether this Technlogy tethered. (Tethering is not supported yet)*/
}connman_proxy_technology_info_t;

/* Callback functions */
typedef struct
{
    connman_proxy_on_update_cb_t    on_update;      /**< Callback for notifying any state changes in network as per connman_proxy_notify_type_t*/
    connman_proxy_on_input_req_cb_t on_input_req;   /**< Callback for notifying any state changes in network as per connman_proxy_notify_type_t*/
    gpointer                        cookie;         /**< User cookie for theses callback functions*/
}connman_proxy_callback_handlers_t;

/**
 * Connman Proxy object handler
 */
typedef struct
{
    GDBusConnection  *connection;       /**< A Glib Dbus connection object to connman Dbus Service*/
    GMainLoop       *loop;              /**< Hanlder for main glib loop*/
    GThread         *context_thread;    /**< Glib thread handler for main context*/

    /* Connman GDbus Proxy Objects*/
    gpointer        manager_proxy;      /**< Proxy object of the connman Manager interface*/
    guint           subscription_id;    /**< Id of the Glib dbus message/signal subscription*/
    guint           watcher_id;         /**< Id of the Glib dbus watcher*/

    char            global_state [8];   /**< Main state of the network system. ("offline", "idle", "ready" and "online"). Where Online means We have internet connection*/
    gboolean        service_available;  /**< Tells if the network service is available or not*/
    gboolean        offline_mode;       /**< Wheteher all interfaces disabled. Similar to airoplane mode*/
    gboolean        session_mode;       /**< Depricated*/
            
    /* Agent Manager parameters*/
    GDBusObjectManagerServer *agent_mgr_server; /**< Glib Dbugs manger object for agent service*/
    gpointer        agent_mgr;          /**< Manager object for the agent service*/
    gchar           *agent_path;        /**< Object path for agent manager interface*/
    gboolean        agent_registered;           /**< Tells whether agent is registered or not*/
    gulong          request_input_sid;          /**< Signal handler for request_input signal*/
    gulong          request_browser_sid;        /**< Signal handler for request_browser signal*/
    gulong          report_error_sid;           /**< Signal handler for report_error signal*/
    gulong          report_peer_error_sid;      /**< Signal handler for report_peer_error signal*/
    gulong          release_sid;                /**< Signal handler for release signal*/
    gulong          cancel_sid;                 /**< Signal handler for cancel signal*/

    /* list of technologies */
    GSList          *technologies;              /**< The list of currently available technologies */

    /* hash table of services */
    GHashTable      *services;                  /**< HasTables that contians currently available service */

    /* signal handler id*/
    gulong service_changed_sid;                 /**< Signal handler for service_changed signal*/
    gulong tech_added_sid;                      /**< Signal handler for technology_added signal*/
    gulong tech_removed_sid;                    /**< Signal handler for technology_removed signal*/

    connman_proxy_callback_handlers_t *cb;       /**< Callback handlers for handling state change and input request */

    gpointer user_data_1;                       /**< User data to be passed to any connman Async API*/
}connman_proxy_handler_t;

/* Connman Proxy Main APIs */

/**
 * De-Initializes a connman proxy handler.
 * Unregisters all the signal handlers. Cleanes up the technology lists and service hash tables.
 * Cleans up all the dbus connection and handlers. Exits the main Glib loop and frees all the memory.
 *
 * @param  connman_proxy_handler A connman proxy handler to cleanup.
 */
void connman_proxy_deinit(connman_proxy_handler_t *connman_proxy_handler);

/**
 * Initializes a new Connman proxy handlers.
 * This will get a connection for SYSTEM BUS and creates manager proxy connection.
 * Add a watcher for service on bus and also register for all the propertyChanged signal of all the interfaces on this service.
 * This will also create a Agent manager interface for wifi activties.
 *
 * @param  cb Contains callback handlers, Refer connman_proxy_callback_handlers_t .
 * @param  cookie User cookie for connman_proxy_on_update_cb_t callback .
 *
 * @returns Newly created connman proxy handler on success, NULL otherwise.
 */
connman_proxy_handler_t* connman_proxy_init(connman_proxy_callback_handlers_t *cb, gpointer cookie);

#if 0 /* For future */
int8_t connman_proxy_get_technologies_full(connman_proxy_handler_t *connman_proxy_handler, GSList *technologies);
int8_t connman_proxy_get_technologies(connman_proxy_handler_t *connman_proxy_handler, char **technologies);
int8_t connman_proxy_get_services_full(connman_proxy_handler_t *connman_proxy_handler, GSList *services);
int8_t connman_proxy_get_services(connman_proxy_handler_t *connman_proxy_handler, char **services);
int8_t connman_proxy_get_service_info(connman_proxy_handler_t *connman_proxy_handler, char *service_id, connman_proxy_service_info_t *service_info);
#endif

/**
 * This method will be used to configure IPv4 configuration of a service.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of a service to be configured
 * @param  method Possible values are "dhcp", "manual", "auto" and "off"
 * @param  addr IPv4 addres to be configured
 * @param  mask Netmask to be configured
 * @param  gw IPv4 gateway to be configured
 *
 * @returns CONNMAN_PROXY_SUCCESS if the call is success, otherwise CONNMAN_PROXY_FAIL
 */
int8_t connman_proxy_configure_ipv4(connman_proxy_handler_t *connman_proxy_handler, char *object_path, char *method, char *addr, char *mask, char *gw);

/**
 * This method will be used to configure IPv6 configuration of a service.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of a service to be configured
 * @param  method Possible values are "auto", "manual", "6to4" and "off".
 * @param  addr IPv6 addres to be configured
 * @param  prefix_len The prefix length of the IPv6 address
 * @param  gw IPv6 gateway to be configured
 * @param  privacy IPv6 privacy extension that is described in RFC 4941. Only if Method is set to "auto".
 *
 * @returns CONNMAN_PROXY_SUCCESS if the call is success, otherwise CONNMAN_PROXY_FAIL
 */
int8_t connman_proxy_configure_ipv6(connman_proxy_handler_t *connman_proxy_handler, char *object_path, char *method, char *addr, uint8_t prefix_len, char *gw, char *privacy);

/**
 * This method will be used to configure proxy of a service.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of a service to be configured
 * @param  method Possible values are "direct", "auto" and "manual"
 * @param  URL Automatic proxy configuration URL. Used by "auto" method.
 * @param  server_list String array of proxy URIs. Used when "manual" method is set.
 * @param  exclude_list String array hosts which can be accessed directly.Used when "manual" method is set.
 *
 * returns CONNMAN_PROXY_SUCCESS if the call is success, otherwise CONNMAN_PROXY_FAIL
 */
int8_t connman_proxy_configure_proxy(connman_proxy_handler_t *connman_proxy_handler, char *object_path, char *method, char *URL, char **server_list, char **exclude_list);

/**
 * This method will be used to configure name servers of a service.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of a service to be configured
 * @param  nameserver_list String array of nameservers ( dns).
 *
 * returns CONNMAN_PROXY_SUCCESS if the call is success, otherwise CONNMAN_PROXY_FAIL
 */
int8_t connman_proxy_configure_nameserver(connman_proxy_handler_t *connman_proxy_handler, char *object_path, char **nameserver_list);

/**
 * This method will be used to configure time servers of a service.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of a service to be configured
 * @param  timeserver_list String array of timeservers.
 *
 * returns CONNMAN_PROXY_SUCCESS if the call is success, otherwise CONNMAN_PROXY_FAIL
 */
int8_t connman_proxy_configure_timeserver(connman_proxy_handler_t *connman_proxy_handler, char *object_path, char **timeserver_list);

/**
 * This method will be used to configure search domain of a service.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of a service to be configured
 * @param  domain_list String array of search domains.
 *
 * returns CONNMAN_PROXY_SUCCESS if the call is success, otherwise CONNMAN_PROXY_FAIL
 */
int8_t connman_proxy_configure_domain(connman_proxy_handler_t *connman_proxy_handler, char *object_path, char **domain_list);

/**
 * This call is used to set autoconnect property of a service.
 * When set to true, the service will auto-connect when no other connection is available
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of a service to be configured for autoconncet
 * @param  autoconnect whether to autoconnect a service or not.
 */
void connman_proxy_set_service_autoconnect(connman_proxy_handler_t *connman_proxy_handler, char *object_path, gboolean autoconnect);

/**
 * This call will power on/off a technology. This is useful when we want to enable wifi/bluetooth interfaces.
 * Bu it will work on ethernet as well.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of an interface to power on/off
 * @param  powered If passed true it will turn the power of interface else it will power down the interface
 */
void connman_proxy_set_technology_power(connman_proxy_handler_t *connman_proxy_handler, char *object_path, gboolean powered);

/**
 * This call will put network system into offline/airoplane mode, all the network activites will be disabled.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  offline If passed true offlin mode will be enabled else it will disable offline mode.
 */
void connman_proxy_set_offline(connman_proxy_handler_t *connman_proxy_handler, gboolean offline);

/**
 * Connect to a service.It will attempt to connect WiFi or Bluetooth services.
 * For Ethernet devices this method can only be used if it has previously been disconnected.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of a service to be removed.
 */
void connman_proxy_connect_service(connman_proxy_handler_t *connman_proxy_handler, char *object_path);

/**
 * Disconnect a service if it is connected.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of a service to be removed.
 */
void connman_proxy_disconnect_service(connman_proxy_handler_t *connman_proxy_handler, char *object_path);

/**
 * A Successfully connected service with Favorite=true
 * can be removed using this async call. If it is connected, it will
 * be automatically disconnected first. This is also used to forget a wifi network.
 * If the service requires a passphrase it will be cleared and forgotten when removing.
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  object_path Object path of a service to be removed.
 */
void connman_proxy_remove_service(connman_proxy_handler_t *connman_proxy_handler, char *object_path);

/**
 * Scan a radio technology to find new services/devices
 *
 * @param  connman_proxy_handler A connman proxy handler
 * @param  technology A technology to scanned. Only supported on WiFi
 */
void connman_proxy_scan_technology(connman_proxy_handler_t *connman_proxy_handler, char *technology);

/***** Util APIs ******/

/**
 * Prints a G_Variant
 *
 * @param key Name of the key
 * @param val Value of the key
 */
void connman_proxy_util_print_g_variant(char *key, GVariant *val);


/**
 * Prints a service object connman_proxy_service_info_t
 *
 * @param  service A service object to print
 */
void connman_proxy_util_print_services(connman_proxy_service_info_t *service);

#endif /* __CONNMAN_PROXY_H */
