/*
   Tunable utilities

   Copyright (C) Amitay Isaacs  2016

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_TUNABLE_H__
#define __CTDB_TUNABLE_H__

#include <stdbool.h>
#include <stdint.h>

#include <talloc.h>

#include "protocol/protocol.h"

void ctdb_tunable_set_defaults(struct ctdb_tunable_list *tun_list);
bool ctdb_tunable_get_value(struct ctdb_tunable_list *tun_list,
			    const char *tunable_str, uint32_t *value);
bool ctdb_tunable_set_value(struct ctdb_tunable_list *tun_list,
			    const char *tunable_str, uint32_t value,
			    bool *obsolete);
struct ctdb_var_list *ctdb_tunable_names(TALLOC_CTX *mem_ctx);
char *ctdb_tunable_names_to_string(TALLOC_CTX *mem_ctx);
bool ctdb_tunable_load_file(TALLOC_CTX *mem_ctx,
			    struct ctdb_tunable_list *tun_list,
			    const char *file);
bool ctdb_tunable_load_directory(TALLOC_CTX *mem_ctx,
				 struct ctdb_tunable_list *tun_list,
				 const char *dir);

#endif /* __CTDB_TUNABLE_H__ */
