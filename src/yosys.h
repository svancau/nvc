//
//  Copyright (C) 2016  Nick Gasson
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

#ifndef _YOSYS_H
#define _YOSYS_H

#include "prim.h"

typedef enum {
   YOSYS_COMMENT,
   YOSYS_LOCATION,
   YOSYS_BEGIN_MODULE,
   YOSYS_END_MODULE,
   YOSYS_WIRE
} yosys_kind_t;

typedef struct {
   yosys_kind_t kind;
   union {
      const char *comment;
      const loc_t location;
      ident_t     begin_module;
      ident_t     wire;
   };
} yosys_cmd_t;

typedef void (*yosys_cmd_fn_t)(const yosys_cmd_t *, void *);

void set_yosys_cmd_fn(yosys_cmd_fn_t fn, void *context);

#endif  // _YOSYS_H
