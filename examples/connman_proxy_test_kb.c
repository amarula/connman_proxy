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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termio.h>
#include <unistd.h>

#include "connman_proxy.h"

static int s_stdin_fd = -1;
static struct termios s_original;

void connman_init_keyboard_input (connman_proxy_handler_t *connman_proxy_handler);
void connman_reset_keyboard_input (void);
gboolean connman_key_is_pressed (int32_t *character);

gboolean
connman_key_is_pressed (int32_t *character)
{
  int characters_buffered = 0;
  gboolean pressed = FALSE;

  if (character == NULL)
    {
      CONNMAN_LOG_WARNING ("Invalid Argument\n");
      return pressed;
    }

  /*Get the number of characters that are waiting to be read*/
  ioctl (s_stdin_fd, FIONREAD, &characters_buffered);
  pressed = (characters_buffered != 0);

  if (characters_buffered == 1)
    *character = fgetc (stdin);
  else if (characters_buffered > 0)
    fflush (stdin);

  return pressed;
}

void
connman_init_keyboard_input (connman_proxy_handler_t *connman_proxy_handler)
{
  struct termios term;

  CONNMAN_PROXY_UNUSED (connman_proxy_handler);
  if (s_stdin_fd == -1)
    {
      s_stdin_fd = fileno (stdin);

      /*Get the terminal (termios) attritubets for stdin*/
      tcgetattr (s_stdin_fd, &s_original);

      /*Copy the termios attributes so we can modify them*/
      memcpy (&term, &s_original, sizeof (term));

      /*Unset ICANON and ECHO for stdin*/
      term.c_lflag &= (tcflag_t) ~(ICANON | ECHO);
      tcsetattr (s_stdin_fd, TCSANOW, &term);

      /*Turn off buffering for stdin*/
      setbuf (stdin, NULL);
    }
  return;
}

void
connman_reset_keyboard_input ()
{
  if (s_stdin_fd != -1)
    {
      tcsetattr (s_stdin_fd, TCSANOW, &s_original);
      s_stdin_fd = -1;
    }
  return;
}
