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
 *  File             : connman_mgr_agent.h
 *  Description      : All the public interface, macros, structures and enums for connman manager(Wifi Agent) are defined here.
 *
 */

#ifndef __CONNMAN_MGR_AGENT_H
#define __CONNMAN_MGR_AGENT_H

/**
 * Maximum length for User Inputs like Wifi passphrase, username  etc
 */
#define CONNMAN_MGR_AGENT_MAX_INPUT_LENGTH 256

/**
 * This method will be used to send response to user input request.
 *
 * @param  input_type Type of input request : connman_mgr_request_input_type_t
 * @param  response Contains response to input request in key-value pair, caller needs to free this if the APi returns FALSE
 *
 * returns TRUE if the call is success, otherwise FALSE
 */
gboolean connman_mgr_set_user_input (connman_mgr_request_input_type_t input_type, GVariant *response);

/**
 * This method will be used to cancel user input request.
 *
 * @param  input_type Type of input request : connman_mgr_request_input_type_t
 */
void connman_mgr_cancel_user_input (connman_mgr_request_input_type_t input_type);

#endif /*__CONNMAN_MGR_AGENT_H*/
