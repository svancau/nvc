//
//  Copyright (C) 2011-2018  Nick Gasson
//  Copyright (C) 2019       Sebastien Van Cauwenberghe
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

#include "phase.h"
#include "util.h"
#include "hash.h"
#include "common.h"
#include "rt/netdb.h"
#include "json.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>

LCOV_EXCL_START

static JsonNode *dump_expr(tree_t t);
static JsonNode *dump_stmt(tree_t t);
static JsonNode *dump_port(tree_t t);
static JsonNode *dump_decl(tree_t t);
static JsonNode *dump_decls(tree_t t);

typedef tree_t (*get_fn_t)(tree_t, unsigned);

JsonNode *base_node = NULL;
JsonNode *return_node = NULL;

static void cannot_dump(tree_t t, const char *hint)
{
   printf("\n");
   fflush(stdout);
   fatal("cannot dump %s kind %s", hint, tree_kind_str(tree_kind(t)));
}

__attribute__((format(printf,1,2)))
static void syntax(const char *fmt, ...)
{
   LOCAL_TEXT_BUF tb = tb_new();
   bool highlighting = false;
   static bool comment = false;
   for (const char *p = fmt; *p != '\0'; p++) {
      if (comment) {
         if (*p == '\n') {
            comment = false;
            tb_printf(tb, "$$");
         }
         if (*p != '~' && *p != '#')
            tb_append(tb, *p);
      }
      else if (*p == '#') {
         tb_printf(tb, "$bold$$cyan$");
         highlighting = true;
      }
      else if (*p == '~') {
         tb_printf(tb, "$yellow$");
         highlighting = true;
      }
      else if (*p == '-' && *(p + 1) == '-') {
         tb_printf(tb, "$red$-");
         comment = true;
      }
      else if (!isalnum((int)*p) && *p != '_' && *p != '%' && highlighting) {
         tb_printf(tb, "$$%c", *p);
         highlighting = false;
      }
      else
         tb_append(tb, *p);
   }

   if (highlighting)
      tb_printf(tb, "$$");

   va_list ap;
   va_start(ap, fmt);
   color_vprintf(tb_get(tb), ap);
   va_end(ap);
}

static JsonNode *dump_params(tree_t t, get_fn_t get, int n, const char *prefix)
{
   JsonNode *params = json_mkarray();
   if (n > 0) {
      for (int i = 0; i < n; i++) {
         JsonNode *element = json_mkobject();
         json_append_element(params, element);
         tree_t p = (*get)(t, i);
         switch (tree_subkind(p)) {
         case P_POS:
            json_append_member(element, "name", json_mknull());
            break;
         case P_NAMED:
            json_append_member(element, "name", dump_expr(tree_name(p)));
            break;
         }
         json_append_member(element, "value", dump_expr(tree_value(p)));
      }
   }
   return params;
}

static JsonNode *dump_range(range_t r)
{
   JsonNode *range_obj = json_mkobject();
   json_append_member(range_obj, "l", dump_expr(r.left));
   switch (r.kind) {
   case RANGE_TO:
      json_append_member(range_obj, "dir", json_mkstring("to")); break;
   case RANGE_DOWNTO:
      json_append_member(range_obj, "dir", json_mkstring("downto")); break;
   case RANGE_DYN:
      json_append_member(range_obj, "dir", json_mkstring("dynamic")); break;
   case RANGE_RDYN:
      json_append_member(range_obj, "dir", json_mkstring("reverse_dynamic")); break;
   case RANGE_EXPR:
      json_append_member(range_obj, "dir", json_mkstring("expr"));
   }
   json_append_member(range_obj, "r", dump_expr(r.right));
   return range_obj;
}

static JsonNode *dump_expr(tree_t t) //TODO: incomplete
{
   JsonNode *expr_node = json_mkobject();
   switch (tree_kind(t)) {
   case T_FCALL:
      json_append_member(expr_node, "cls", json_mkstring("fcall"));
      json_append_member(expr_node, "name", json_mkstring(istr(tree_ident(tree_ref(t)))));
      json_append_member(expr_node, "params", dump_params(t, tree_param, tree_params(t), NULL));
      break;

   case T_LITERAL:
      switch (tree_subkind(t)) {
      case L_INT:
         json_append_member(expr_node, "cls", json_mkstring("int"));
         json_append_member(expr_node, "value", json_mknumber(tree_ival(t)));
         break;
      case L_REAL:
         json_append_member(expr_node, "cls", json_mkstring("real"));
         json_append_member(expr_node, "value", json_mknumber(tree_dval(t)));
         break;
      case L_NULL:
         json_append_member(expr_node, "cls", json_mkstring("null"));
         json_append_member(expr_node, "value", json_mknull());
         break;
      case L_STRING:
         json_append_member(expr_node, "cls", json_mkstring("string"));
         {
            printf("\"");
            const int nchars = tree_chars(t);
            for (int i = 0; i < nchars; i++)
               printf("%c", ident_char(tree_ident(tree_char(t, i)), 1));
            printf("\"");
         }
         break;
      default:
         assert(false);
      }
      break;

   case T_NEW:
      json_append_member(expr_node, "cls", json_mkstring("new"));
      json_append_member(expr_node, "op", dump_expr(tree_value(t)));
      break;

   case T_ALL:
      dump_expr(tree_value(t));
      printf(".all");
      break;

   case T_AGGREGATE:
      printf("(");
      for (unsigned i = 0; i < tree_assocs(t); i++) {
         if (i > 0)
            printf(", ");
         tree_t a = tree_assoc(t, i);
         tree_t value = tree_value(a);
         switch (tree_subkind(a)) {
         case A_POS:
            dump_expr(value);
            break;
         case A_NAMED:
            dump_expr(tree_name(a));
            printf(" => ");
            dump_expr(value);
            break;
         case A_OTHERS:
            printf("others => ");
            dump_expr(value);
            break;
         case A_RANGE:
            dump_range(tree_range(a, 0));
            printf(" => ");
            dump_expr(value);
            break;
         default:
            assert(false);
         }
      }
      printf(")");
      break;

   case T_REF:
      json_append_member(expr_node, "cls", json_mkstring("ref"));
      json_append_member(expr_node, "name", json_mkstring(istr(tree_ident(tree_ref(t)))));
      break;

   case T_ATTR_REF:
      json_append_member(expr_node, "cls", json_mkstring("attr"));
      json_append_member(expr_node, "name", json_mkstring( istr(tree_ident(t))));
      json_append_member(expr_node, "op", dump_expr(tree_name(t)));
      break;

   case T_ARRAY_REF:
      dump_expr(tree_value(t));
      dump_params(t, tree_param, tree_params(t), NULL);
      break;

   case T_ARRAY_SLICE:
      dump_expr(tree_value(t));
      printf("(");
      dump_range(tree_range(t, 0));
      printf(")");
      break;

   case T_RECORD_REF:
      dump_expr(tree_value(t));
      printf(".%s", istr(tree_ident(t)));
      break;

   case T_TYPE_CONV:
      printf("%s(", istr(tree_ident(tree_ref(t))));
      dump_expr(tree_value(tree_param(t, 0)));
      printf(")");
      break;

   case T_CONCAT:
      {
         printf("(");
         const int nparams = tree_params(t);
         for (int i = 0; i < nparams; i++) {
            if (i > 0)
               printf(" & ");
            dump_expr(tree_value(tree_param(t, i)));
         }
         printf(")");
      }
      break;

   case T_QUALIFIED:
      printf("%s'(", istr(type_ident(tree_type(t))));
      dump_expr(tree_value(t));
      printf(")");
      break;

   case T_OPEN:
      json_append_member(expr_node, "cls", json_mkstring("open"));
      break;

   default:
      cannot_dump(t, "expr");
   }
   return expr_node;
}

static const char *dump_minify_type(const char *name)
{
   static const char *known[] = {
      "STD.STANDARD.",
      "IEEE.NUMERIC_STD.",
      "IEEE.STD_LOGIC_1164.",
   };

   for (size_t i = 0; i < ARRAY_LEN(known); i++) {
      const size_t len = strlen(known[i]);
      if (strncmp(name, known[i], len) == 0) {
         static char buf[256];
         checked_sprintf(buf, sizeof(buf), "~%s%%s", name + len);
         return buf;
      }
   }

   return name;
}

static JsonNode *dump_type(type_t type)
{
   JsonNode *type_node = json_mkobject();
   
   if (type_kind(type) == T_SUBTYPE && type_has_ident(type))
      json_append_member(type_node, "name", json_mkstring(type_pp_minify(type, dump_minify_type)+1));
   else if (type_is_array(type) && !type_is_unconstrained(type)) {
      json_append_member(type_node, "name", json_mkstring(type_pp_minify(type, dump_minify_type)+1));
      const int ndims = array_dimension(type);
      JsonNode *range = json_mkarray();
      json_append_member(type_node, "range", range);
      for (int i = 0; i < ndims; i++) {
         JsonNode *range_obj = json_mkobject();
         range_t r = range_of(type, i);
         json_append_member(range_obj, "l", dump_expr(r.left));
         
         switch (r.kind) {
         case RANGE_TO:
            json_append_member(range_obj, "dir", json_mkstring("to"));
            json_append_member(range_obj, "r", dump_expr(r.right));
            break;
         case RANGE_DOWNTO:
            json_append_member(range_obj, "dir", json_mkstring("downto"));
            json_append_member(range_obj, "r", dump_expr(r.right));
            break;
         case RANGE_DYN:
            json_append_member(range_obj, "dir", json_mkstring("dynamic"));
            json_append_member(range_obj, "r", dump_expr(r.right));
            break;
         case RANGE_RDYN:
            json_append_member(range_obj, "dir", json_mkstring("reverse_dynamic"));
            json_append_member(range_obj, "r", dump_expr(r.right));
            break;
         case RANGE_EXPR:
            break;
         }
         json_append_element(range, range_obj);
      }
   }
   else
      json_append_member(type_node, "name", json_mkstring(type_pp_minify(type, dump_minify_type)+1));
   return type_node;
}

static void dump_op(tree_t t, int indent)
{

   syntax("-- predefined %s [", istr(tree_ident(t)));

   const int nports = tree_ports(t);
   for (int i = 0; i < nports; i++) {
      dump_type(tree_type(tree_port(t, i)));
      if (i + 1 < nports)
         printf(", ");
   }

   printf("]");

   if (tree_kind(t) == T_FUNC_DECL) {
      printf(" return ");
      dump_type(type_result(tree_type(t)));
   }

   syntax("\n");
}

static void dump_ports(tree_t t, int indent)
{
   const int nports = tree_ports(t);
   if (nports > 0) {
      if (nports > 1) {
         printf(" (\n");
         indent += 4;
      }
      else {
         printf(" (");
         indent = 0;
      }
      for (int i = 0; i < nports; i++) {
         if (i > 0)
            printf(";\n");
         dump_port(tree_port(t, i));
      }
      printf(" )");
   }
}

static void dump_block(tree_t t)
{
   const int ndecls = tree_decls(t);
   for (unsigned i = 0; i < ndecls; i++)
      dump_decl(tree_decl(t, i));
   syntax("#begin\n");
   const int nstmts = tree_stmts(t);
   for (int i = 0; i < nstmts; i++)
      dump_stmt(tree_stmt(t, i));
}

static void dump_wait_level(tree_t t)
{
   switch (tree_attr_int(t, wait_level_i, WAITS_MAYBE)) {
   case WAITS_NO:
      syntax("   -- Never waits");
      break;
   case WAITS_MAYBE:
      syntax("   -- Maybe waits");
      break;
   case WAITS_YES:
      syntax("   -- Waits");
      break;
   }
}

static JsonNode *dump_decl(tree_t t)
{
   JsonNode *decl = json_mkobject();

   switch (tree_kind(t)) {
   case T_SIGNAL_DECL:
      json_append_member(decl, "cls", json_mkstring("sigdecl"));
      json_append_member(decl, "name", json_mkstring(istr(tree_ident(t))));
      break;

   case T_VAR_DECL:
      json_append_member(decl, "cls", json_mkstring("vardecl"));
      json_append_member(decl, "name", json_mkstring(istr(tree_ident(t))));
      break;

   case T_CONST_DECL:
      json_append_member(decl, "cls", json_mkstring("constdecl"));
      json_append_member(decl, "name", json_mkstring(istr(tree_ident(t))));
      break;

   case T_TYPE_DECL:
      {
         type_t type = tree_type(t);
         type_kind_t kind = type_kind(type);
         bool is_subtype = (kind == T_SUBTYPE);

         printf("%stype %s is ", is_subtype ? "sub" : "", istr(tree_ident(t)));

         if (is_subtype) {
            printf("%s ", istr(type_ident(type_base(type))));
         }

         if (type_is_integer(type) || type_is_real(type)) {
            printf("range ");
            dump_range(type_dim(type, 0));
         }
         else if (type_is_physical(type)) {
            printf("range ");
            dump_range(type_dim(type, 0));
            printf("\n");
            printf("units\n");
            {
               const int nunits = type_units(type);
               for (int i = 0; i < nunits; i++) {
                  tree_t u = type_unit(type, i);
                  printf("%s = ", istr(tree_ident(u)));
                  dump_expr(tree_value(u));
                  printf(";\n");
               }
            }
            printf("end units\n");
         }
         else if (type_is_array(type)) {
            if (!is_subtype)
               printf("array ");
            printf("(");
            if (kind == T_UARRAY) {
               const int nindex = type_index_constrs(type);
               for (int i = 0; i < nindex; i++) {
                  if (i > 0) printf(", ");
                  dump_type(type_index_constr(type, i));
                  printf(" range <>");
               }
            }
            else if (kind == T_SUBTYPE) {
               tree_t constraint = type_constraint(type);
               const int nranges = tree_ranges(constraint);
               for (int i = 0; i < nranges; i++) {
                  if (i > 0) printf(", ");
                  dump_range(tree_range(constraint, i));
               }
            }
            else {
               const int ndims = type_dims(type);
               for (int i = 0; i < ndims; i++) {
                  if (i > 0) printf(", ");
                  dump_range(type_dim(type, i));
               }
            }
            printf(")");
            if (!is_subtype) {
               printf(" of ");
               dump_type(type_elem(type));
            }
         }
         else if (type_is_protected(type)) {
            printf("protected\n");
            for (unsigned i = 0; i < type_decls(type); i++)
               dump_decl(type_decl(type, i));

            printf("end protected");
         }
         else if (kind == T_ENUM) {
            printf("(");
            for (unsigned i = 0; i < type_enum_literals(type); i++) {
               if (i > 0) printf(", ");
               printf("%s", istr(tree_ident(type_enum_literal(type, i))));
            }
            printf(")");
         }
         else
            dump_type(type);
      }
      printf(";\n");
      {
         const int nops = tree_ops(t);
         for (int i = 0; i < nops; i++)
            dump_op(tree_op(t, i), 0);
      }
      return decl;

   case T_SPEC:
      syntax("#for %s\n", istr(tree_ident(t)));
      syntax("#end #for;\n");
      return decl;

   case T_BLOCK_CONFIG:
      syntax("#for %s\n", istr(tree_ident(t)));
      dump_decls(t);
      syntax("#end #for;\n");
      return decl;

   case T_ALIAS:
      printf("alias %s : ", istr(tree_ident(t)));
      dump_type(tree_type(t));
      printf(" is ");
      dump_expr(tree_value(t));
      printf(";\n");
      return decl;

   case T_ATTR_SPEC:
      syntax("#attribute %s #of %s : #%s #is ", istr(tree_ident(t)),
             istr(tree_ident2(t)), class_str(tree_class(t)));
      dump_expr(tree_value(t));
      printf(";\n");
      return decl;

   case T_ATTR_DECL:
      syntax("#attribute %s : ", istr(tree_ident(t)));
      dump_type(tree_type(t));
      printf(";\n");
      return decl;

   case T_GENVAR:
      syntax("#genvar %s : ", istr(tree_ident(t)));
      dump_type(tree_type(t));
      printf(";\n");
      return decl;

   case T_FUNC_DECL:
      syntax("#function %s", istr(tree_ident(t)));
      dump_ports(t, 0);
      syntax(" #return %s;\n", type_pp(type_result(tree_type(t))));
      return decl;

   case T_FUNC_BODY:
      syntax("#function %s", istr(tree_ident(t)));
      dump_ports(t, 0);
      syntax(" #return %s #is\n", type_pp(type_result(tree_type(t))));
      dump_block(t);
      syntax("#end #function;\n\n");
      return decl;

   case T_PROC_DECL:
      syntax("#procedure %s", istr(tree_ident(t)));
      dump_ports(t, 0);
      printf(";");
      dump_wait_level(t);
      printf("\n");
      return decl;

   case T_PROC_BODY:
      syntax("#procedure %s", istr(tree_ident(t)));
      dump_ports(t, 0);
      syntax(" #is");
      dump_wait_level(t);
      printf("\n");
      dump_block(t);
      syntax("#end #procedure;\n\n");
      return decl;

   case T_HIER:
      syntax("-- Enter scope %s\n", istr(tree_ident(t)));
      return decl;

   case T_COMPONENT:
      syntax("#component %s is\n", istr(tree_ident(t)));
      if (tree_generics(t) > 0) {
         syntax("    #generic (\n");
         for (unsigned i = 0; i < tree_generics(t); i++) {
            if (i > 0)
               printf(";\n");
            dump_port(tree_generic(t, i));
         }
         printf(" );\n");
      }
      if (tree_ports(t) > 0) {
         syntax("    #port (\n");
         for (unsigned i = 0; i < tree_ports(t); i++) {
            if (i > 0)
               printf(";\n");
            dump_port(tree_port(t, i));
         }
         printf(" );\n");
      }
      syntax("  #end #component;\n");
      return decl;

   case T_PROT_BODY:
      syntax("type %s #is #protected #body\n", istr(tree_ident(t)));
      for (unsigned i = 0; i < tree_decls(t); i++)
         dump_decl(tree_decl(t, i));
      syntax("#end #protected #body;\n");
      return decl;

   case T_FILE_DECL:
      syntax("#file %s : ", istr(tree_ident(t)));
      dump_type(tree_type(t));
      if (tree_has_value(t)) {
         syntax(" #open ");
         dump_expr(tree_file_mode(t));
         syntax(" #is ");
         dump_expr(tree_value(t));
      }
      printf(";\n");
      return decl;

   case T_USE:
      syntax("#use %s", istr(tree_ident(t)));
      if (tree_has_ident2(t))
         printf(".%s", istr(tree_ident2(t)));
      printf(";\n");
      return decl;

   default:
      cannot_dump(t, "decl");
   }

   json_append_member(decl, "type", dump_type(tree_type(t)));

   if (tree_has_value(t))
      json_append_member(decl, "val", dump_expr(tree_value(t)));
   else
      json_append_member(decl, "val", json_mknull());

   if (tree_attr_int(t, ident_new("returned"), 0))
      printf(" -- returned");

   return decl;
}

static JsonNode *dump_stmt(tree_t t)
{
   JsonNode *statement = json_mkobject();
   JsonNode *stmt = json_mkarray();
   switch (tree_kind(t)) {
   case T_PROCESS:
      json_append_member(statement, "cls", json_mkstring("process"));
      json_append_member(statement, "decls", dump_decls(t));
      json_append_member(statement, "stmts", stmt);
      for (unsigned i = 0; i < tree_stmts(t); i++)
         json_append_element(stmt, dump_stmt(tree_stmt(t, i)));
      break;

   case T_SIGNAL_ASSIGN:
      json_append_member(statement, "cls", json_mkstring("sigassign"));
      json_append_member(statement, "target", dump_expr(tree_target(t)));
      /* Delays are not translated */
      if (tree_waveforms(t)) {
         tree_t w = tree_waveform(t, 0);
         json_append_member(statement, "lhs", dump_expr(tree_value(w)));
      }
      break;

   case T_VAR_ASSIGN:
      json_append_member(statement, "cls", json_mkstring("varassign"));
      dump_expr(tree_target(t));
      printf(" := ");
      dump_expr(tree_value(t));
      break;

   case T_WAIT:
      json_append_member(statement, "cls", json_mkstring("wait"));
      JsonNode *wait_on = json_mkarray();
      json_append_member(statement, "on", wait_on);
      if (tree_triggers(t) > 0) {
         for (unsigned i = 0; i < tree_triggers(t); i++) {
            json_append_element(wait_on, dump_expr(tree_trigger(t, i)));
         }
      }
      break;

   case T_BLOCK:
      json_append_member(statement, "cls", json_mkstring("block"));
      syntax("#block #is\n");
      dump_block(t);
      syntax("#end #block");
      break;

   case T_ASSERT:
      json_append_member(statement, "cls", json_mkstring("assert"));
      if (tree_has_value(t)) {
         syntax("#assert ");
         dump_expr(tree_value(t));
      }
      if (tree_has_message(t)) {
         syntax(" #report ");
         dump_expr(tree_message(t));
      }
      syntax(" #severity ");
      dump_expr(tree_severity(t));
      break;

   case T_WHILE:
      json_append_member(statement, "cls", json_mkstring("while"));
      if (tree_has_value(t)) {
         syntax("#while ");
         dump_expr(tree_value(t));
         printf(" ");
      }
      syntax("#loop\n");
      for (unsigned i = 0; i < tree_stmts(t); i++)
         dump_stmt(tree_stmt(t, i));
      syntax("#end #loop");
      break;

   case T_IF:
      json_append_member(statement, "cls", json_mkstring("if"));
      json_append_member(statement, "cond", dump_expr(tree_value(t)));
      JsonNode *then_node = json_mkarray();
      json_append_member(statement, "then", then_node);
      JsonNode *else_node = json_mkarray();
      json_append_member(statement, "else", else_node);
      for (unsigned i = 0; i < tree_stmts(t); i++)
         json_append_element(then_node, dump_stmt(tree_stmt(t, i)));
      if (tree_else_stmts(t) > 0) {
         for (unsigned i = 0; i < tree_else_stmts(t); i++)
            json_append_element(else_node, dump_stmt(tree_else_stmt(t, i)));
      }
      break;

   case T_EXIT:
      json_append_member(statement, "cls", json_mkstring("exit"));
      syntax("#exit %s", istr(tree_ident2(t)));
      if (tree_has_value(t)) {
         syntax(" #when ");
         dump_expr(tree_value(t));
      }
      break;

   case T_CASE:
      json_append_member(statement, "cls", json_mkstring("case"));
      syntax("#case ");
      dump_expr(tree_value(t));
      syntax(" #is\n");
      for (unsigned i = 0; i < tree_assocs(t); i++) {
         tree_t a = tree_assoc(t, i);
         switch (tree_subkind(a)) {
         case A_NAMED:
            syntax("#when ");
            dump_expr(tree_name(a));
            printf(" =>\n");
            break;
         case A_OTHERS:
            syntax("#when #others =>\n");
            break;
         default:
            assert(false);
         }
         dump_stmt(tree_value(a));
      }
      syntax("#end #case");
      break;

   case T_RETURN:
      json_append_member(statement, "cls", json_mkstring("return"));
      syntax("#return");
      if (tree_has_value(t)) {
         printf(" ");
         dump_expr(tree_value(t));
      }
      break;

   case T_FOR:
      json_append_member(statement, "cls", json_mkstring("for"));
      syntax("#for %s #in ", istr(tree_ident2(t)));
      dump_range(tree_range(t, 0));
      syntax(" #loop\n");
      for (unsigned i = 0; i < tree_stmts(t); i++)
         dump_stmt(tree_stmt(t, i));
      syntax("#end #for");
      break;

   case T_PCALL:
      json_append_member(statement, "cls", json_mkstring("pcall"));
      printf("%s", istr(tree_ident(tree_ref(t))));
      dump_params(t, tree_param, tree_params(t), NULL);
      break;

   case T_FOR_GENERATE:
      json_append_member(statement, "cls", json_mkstring("for_generate"));
      syntax("#for %s #in ", istr(tree_ident2(t)));
      dump_range(tree_range(t, 0));
      syntax(" #generate\n");
      for (unsigned i = 0; i < tree_decls(t); i++)
         dump_decl(tree_decl(t, i));
      syntax("#begin\n");
      for (unsigned i = 0; i < tree_stmts(t); i++)
         dump_stmt(tree_stmt(t, i));
      syntax("end generate");
      break;

   case T_IF_GENERATE:
      json_append_member(statement, "cls", json_mkstring("if_generate"));
      syntax("#if ");
      dump_expr(tree_value(t));
      syntax(" #generate\n");
      for (unsigned i = 0; i < tree_decls(t); i++)
         dump_decl(tree_decl(t, i));
      syntax("#begin\n");
      for (unsigned i = 0; i < tree_stmts(t); i++)
         dump_stmt(tree_stmt(t, i));
      syntax("#end #generate");
      break;

   case T_INSTANCE:
      json_append_member(statement, "cls", json_mkstring("instance"));
      switch (tree_class(t)) {
      case C_ENTITY:    syntax("#entity "); break;
      case C_COMPONENT: syntax("#component "); break;
      default:
         assert(false);
      }
      printf("%s", istr(tree_ident2(t)));
      if (tree_has_spec(t)) {
         tree_t bind = tree_value(tree_spec(t));
         syntax(" -- bound to %s", istr(tree_ident(bind)));
         if (tree_has_ident2(bind))
            printf("(%s)", istr(tree_ident2(bind)));
      }
      printf("\n");
      if (tree_genmaps(t) > 0) {
         dump_params(t, tree_genmap, tree_genmaps(t), "#generic #map");
         printf("\n");
      }
      if (tree_params(t) > 0) {
         dump_params(t, tree_param, tree_params(t), "#port #map");
      }
      printf(";\n\n");
      break;

   case T_NEXT:
      json_append_member(statement, "cls", json_mkstring("next"));
      syntax("#next");
      if (tree_has_value(t)) {
         syntax(" #when ");
         dump_expr(tree_value(t));
      }
      break;

   default:
      cannot_dump(t, "stmt");
   }

   return statement;
}

static JsonNode *dump_port(tree_t t)
{
   JsonNode *port = json_mkobject();
   json_append_member(port, "name", json_mkstring(istr(tree_ident(t))));

   const char *class = NULL, *dir = NULL;
   switch (tree_class(t)) {
   case C_SIGNAL:   class = "signal";   break;
   case C_VARIABLE: class = "variable"; break;
   case C_DEFAULT:  class = "";         break;
   case C_CONSTANT: class = "constant"; break;
   case C_FILE:     class = "file";     break;
   default:
      assert(false);
   }
   json_append_member(port, "class", json_mkstring(class));
   switch (tree_subkind(t)) {
   case PORT_IN:      dir = "in";     break;
   case PORT_OUT:     dir = "out";    break;
   case PORT_INOUT:   dir = "inout";  break;
   case PORT_BUFFER:  dir = "buffer"; break;
   case PORT_INVALID: dir = "??";     break;
   }
   json_append_member(port, "dir", json_mkstring(dir));
   json_append_member(port, "type", dump_type(tree_type(t)));
   return port;
}

static void dump_context(tree_t t)
{
   const int nctx = tree_contexts(t);
   for (int i = 0; i < nctx; i++) {
      tree_t c = tree_context(t, i);
      switch (tree_kind(c)) {
      case T_LIBRARY:
         if (tree_ident(c) != std_i && tree_ident(c) != work_i)
            syntax("#library %s;\n", istr(tree_ident(c)));
         break;

      case T_USE:
         syntax("#use %s", istr(tree_ident(c)));
         if (tree_has_ident2(c)) {
            printf(".%s", istr(tree_ident2(c)));
         }
         printf(";\n");
         break;

      default:
         break;
      }
   }

   if (nctx > 0)
      printf("\n");
}

static void dump_elab(tree_t t)
{
   dump_context(t);
   syntax("#entity %s #is\n#end #entity;\n\n", istr(tree_ident(t)));
   syntax("#architecture #elab #of %s #is\n", istr(tree_ident(t)));
   dump_decls(t);
   syntax("#begin\n");
   for (unsigned i = 0; i < tree_stmts(t); i++)
      dump_stmt(tree_stmt(t, i));
   syntax("#end #architecture;\n");
}

static void dump_entity(tree_t t)
{
   JsonNode *entity_node = json_mkobject();
   dump_context(t);
   json_append_member(entity_node, "name", json_mkstring(istr(tree_ident(t))));
   JsonNode *generic_array = json_mkarray();
   if (tree_generics(t) > 0) {
      for (unsigned i = 0; i < tree_generics(t); i++) {
         json_append_element(generic_array, dump_port(tree_generic(t, i)));
      }
   }
   json_append_member(entity_node, "generic", generic_array);

   JsonNode *port_array = json_mkarray();
   if (tree_ports(t) > 0) {
      for (unsigned i = 0; i < tree_ports(t); i++) {
         json_append_element(port_array, dump_port(tree_port(t, i)));
      }
   }
   json_append_member(entity_node, "port", port_array);
   json_append_member(entity_node, "decls", dump_decls(t));

   JsonNode *stmts_array = json_mkarray();
   for (unsigned i = 0; i < tree_stmts(t); i++) {
      json_append_element(stmts_array, dump_stmt(tree_stmt(t, i)));
   }
   json_append_member(entity_node, "stmts", stmts_array);
   return_node = entity_node;
}

static JsonNode *dump_decls(tree_t t)
{
   JsonNode *decls = json_mkarray();
   const int ndecls = tree_decls(t);
   for (unsigned i = 0; i < ndecls; i++)
      json_append_element(decls, dump_decl(tree_decl(t, i)));
   return decls;
}

static void dump_arch(tree_t t)
{
   JsonNode *architecture_node = json_mkobject();
   dump_context(t);
   json_append_member(architecture_node, "name", json_mkstring(istr(tree_ident(t))));
   json_append_member(architecture_node, "of", json_mkstring(istr(tree_ident2(t))));
   json_append_member(architecture_node, "decls", dump_decls(t));
   JsonNode *stmts_array = json_mkarray();
   for (unsigned i = 0; i < tree_stmts(t); i++)
      json_append_element(stmts_array, dump_stmt(tree_stmt(t, i)));
   json_append_member(architecture_node, "stmts", stmts_array);
   return_node = architecture_node;
}

static void dump_package(tree_t t)
{
   dump_context(t);
   syntax("#package %s #is\n", istr(tree_ident(t)));
   dump_decls(t);
   syntax("#end #package;\n");
}

static void dump_package_body(tree_t t)
{
   dump_context(t);
   syntax("#package #body %s #is\n", istr(tree_ident(t)));
   dump_decls(t);
   syntax("#end #package #body;\n");
}

static void dump_configuration(tree_t t)
{
   syntax("#configuration %s #of %s #is\n",
          istr(tree_ident(t)), istr(tree_ident2(t)));
   dump_decls(t);
   syntax("#end #configuration\n");
}

void dump_json(tree_t *elements, unsigned int n_elements, const char *filename)
{
   FILE* dump_file = fopen(filename, "w");
   if (!dump_file) {
      fclose(dump_file);
      return;
   }

   unsigned int i;
   char *result;
   base_node = json_mkobject();
   for(i=0; i < n_elements; i++) {
      tree_t t = elements[i];
      switch (tree_kind(t)) {
      case T_ELAB:
         dump_elab(t);
         break;
      case T_ENTITY:
         dump_entity(t);
         json_append_member(base_node, "entity", return_node);
         break;
      case T_ARCH:
         dump_arch(t);
         json_append_member(base_node, "architecture", return_node);
         break;
      case T_PACKAGE:
         dump_package(t);
         break;
      case T_PACK_BODY:
         dump_package_body(t);
         break;
      case T_CONFIGURATION:
         dump_configuration(t);
         break;
      case T_FCALL:
      case T_LITERAL:
      case T_AGGREGATE:
      case T_REF:
      case T_ARRAY_REF:
      case T_ARRAY_SLICE:
      case T_TYPE_CONV:
      case T_CONCAT:
      case T_RECORD_REF:
         dump_expr(t);
         printf("\n");
         break;
      case T_FOR_GENERATE:
      case T_BLOCK:
      case T_PROCESS:
      case T_CASE:
      case T_FOR:
         dump_stmt(t);
         break;
      case T_CONST_DECL:
      case T_VAR_DECL:
      case T_SIGNAL_DECL:
         dump_decl(t);
         break;
      default:
         cannot_dump(t, "tree");
      }
   }
   result = json_encode(base_node);
   fwrite(result, 1, strlen(result), dump_file);
   fclose(dump_file);
   json_delete(base_node);
}

LCOV_EXCL_STOP