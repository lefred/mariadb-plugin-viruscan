/* Copyright (c) 2019,2024,2025,2026 MariaDB Corporation
   Copyright (c) 2026 lefred (Frédéric Descamps)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1335  USA */

#define MYSQL_SERVER

#include <my_global.h>
#include <my_sys.h>
#include <mysql/plugin.h>
#include <sql_acl.h>
#include <sql_class.h>
#include <sql_i_s.h>
#include <sql_show.h>
#include <item_create.h>
#include <mysql/plugin_function.h>
#include <tztime.h>

#include <array>
#include <cstring>
#include <ctime>
#include <string>

#include <clamav.h>

namespace {

constexpr size_t VIRUS_MAX_ROWS= 10;

struct Virus_record
{
  time_t timestamp;
  std::string name;
  std::string user;
  std::string host;
  std::string engine;
  ulong signatures;
};

static mysql_mutex_t LOCK_viruscan_engine;
static mysql_mutex_t LOCK_viruscan_history;
static mysql_mutex_t LOCK_viruscan_reload;
static PSI_mutex_key key_viruscan_engine;
static PSI_mutex_key key_viruscan_history;
static PSI_mutex_key key_viruscan_reload;

static PSI_mutex_info viruscan_mutexes[]=
{
  {&key_viruscan_engine, "engine", PSI_FLAG_GLOBAL},
  {&key_viruscan_history, "history", PSI_FLAG_GLOBAL},
  {&key_viruscan_reload, "reload", PSI_FLAG_GLOBAL}
};

static cl_engine *viruscan_engine;
static cl_stat viruscan_signature_stat;
static bool viruscan_signature_stat_initialized;
static std::array<Virus_record, VIRUS_MAX_ROWS> viruscan_history;
static size_t viruscan_history_start;
static size_t viruscan_history_size;
static ulong viruscan_signatures;
static ulonglong viruscan_virus_found;
static char viruscan_clamav_version[64];

static SHOW_VAR viruscan_status_variables[]=
{
  {"clamav_signatures", reinterpret_cast<char *>(&viruscan_signatures),
   SHOW_LONG},
  {"clamav_engine_version", viruscan_clamav_version,
   SHOW_CHAR},
  {"virus_found", reinterpret_cast<char *>(&viruscan_virus_found),
   SHOW_LONGLONG},
  {nullptr, nullptr, SHOW_UNDEF}
};

static void add_match(THD *thd, const std::string &name, ulong signatures)
{
  mysql_mutex_lock(&LOCK_viruscan_history);
  size_t index;
  if (viruscan_history_size < VIRUS_MAX_ROWS)
  {
    index= (viruscan_history_start + viruscan_history_size) % VIRUS_MAX_ROWS;
    ++viruscan_history_size;
  }
  else
  {
    index= viruscan_history_start;
    viruscan_history_start= (viruscan_history_start + 1) % VIRUS_MAX_ROWS;
  }

  Virus_record &record= viruscan_history[index];
  record.timestamp= time(nullptr);
  record.name= name;
  record.user= thd->security_ctx->priv_user;
  record.host= thd->security_ctx->priv_host_name();
  record.engine= viruscan_clamav_version;
  record.signatures= signatures;
  ++viruscan_virus_found;
  mysql_mutex_unlock(&LOCK_viruscan_history);
}

static int load_engine()
{
  uint signatures= 0;
  cl_engine *new_engine= cl_engine_new();
  if (!new_engine)
  {
    sql_print_error("viruscan: cannot allocate the ClamAV engine");
    return 1;
  }

  const char *database_dir= cl_retdbdir();
  cl_error_t error= cl_load(database_dir, new_engine, &signatures, CL_DB_STDOPT);
  if (error != CL_SUCCESS)
  {
    sql_print_error("viruscan: cannot load ClamAV databases from %s: %s",
                    database_dir, cl_strerror(error));
    cl_engine_free(new_engine);
    return 1;
  }

  error= cl_engine_compile(new_engine);
  if (error != CL_SUCCESS)
  {
    sql_print_error("viruscan: cannot compile the ClamAV engine: %s",
                    cl_strerror(error));
    cl_engine_free(new_engine);
    return 1;
  }

  mysql_mutex_lock(&LOCK_viruscan_engine);
  cl_engine *old_engine= viruscan_engine;
  viruscan_engine= new_engine;
  viruscan_signatures= signatures;
  mysql_mutex_unlock(&LOCK_viruscan_engine);
  if (old_engine)
    cl_engine_free(old_engine);

  sql_print_information("viruscan: loaded %u signatures from %s",
                        signatures, database_dir);
  return 0;
}

static bool require_super(THD *thd)
{
  return check_global_access(thd, SUPER_ACL, false);
}

class Item_func_virus_scan final : public Item_str_func
{
public:
  Item_func_virus_scan(THD *thd, Item *arg) : Item_str_func(thd, arg) {}

  bool fix_length_and_dec(THD *) override
  {
    max_length= 400 * my_charset_utf8mb4_general_ci.mbmaxlen;
    collation.set(&my_charset_utf8mb4_general_ci);
    set_maybe_null();
    return false;
  }

  String *val_str(String *result) override
  {
    StringBuffer<1024> input_buffer;
    String *input= args[0]->val_str(&input_buffer);
    if (!input)
    {
      null_value= true;
      return nullptr;
    }
    if (require_super(current_thd))
    {
      null_value= true;
      return nullptr;
    }

    const char *virus_name= nullptr;
    ulong scanned= 0;
    cl_scan_options options;
    memset(&options, 0, sizeof(options));
    options.parse= ~0U;
    options.general= CL_SCAN_GENERAL_ALLMATCHES;

    std::string matched_name;
    ulong matched_signatures= 0;

    mysql_mutex_lock(&LOCK_viruscan_engine);
    cl_error_t error;
    if (!viruscan_engine)
      error= CL_ESTATE;
    else
    {
      cl_fmap_t *map= cl_fmap_open_memory(input->ptr(), input->length());
      if (!map)
        error= CL_EMEM;
      else
      {
        error= cl_scanmap_callback(map, nullptr, &virus_name, &scanned,
                                   viruscan_engine, &options, nullptr);
        cl_fmap_close(map);
      }
    }
    if (error == CL_VIRUS)
    {
      /* Copy while the engine is still locked: virus_name points into
         engine memory that a concurrent virus_reload_engine() could free
         as soon as the lock is released. */
      matched_name= virus_name ? virus_name : "unknown";
      matched_signatures= viruscan_signatures;
    }
    mysql_mutex_unlock(&LOCK_viruscan_engine);

    if (error == CL_VIRUS)
    {
      add_match(current_thd, matched_name, matched_signatures);
      sql_print_information("viruscan: virus found: %s", matched_name.c_str());
      null_value= result->copy(matched_name.data(), matched_name.length(),
                              &my_charset_utf8mb4_general_ci);
    }
    else if (error == CL_CLEAN)
      null_value= result->copy(STRING_WITH_LEN("clean: no virus found"),
                              &my_charset_utf8mb4_general_ci);
    else
    {
      my_printf_error(ER_UNKNOWN_ERROR, "viruscan: ClamAV scan failed: %s",
                      MYF(0), cl_strerror(error));
      null_value= true;
    }
    return null_value ? nullptr : result;
  }

  LEX_CSTRING func_name_cstring() const override
  {
    return "virus_scan"_LEX_CSTRING;
  }

  Item *shallow_copy(THD *thd) const override
  {
    return get_item_copy<Item_func_virus_scan>(thd, this);
  }
};

class Create_func_virus_scan final : public Create_func_arg1
{
public:
  Item *create_1_arg(THD *thd, Item *arg) override
  {
    return new (thd->mem_root) Item_func_virus_scan(thd, arg);
  }
};

class Item_func_virus_reload final : public Item_str_func
{
public:
  explicit Item_func_virus_reload(THD *thd) : Item_str_func(thd) {}

  bool fix_length_and_dec(THD *) override
  {
    max_length= 128;
    collation.set(&my_charset_utf8mb4_general_ci);
    set_maybe_null();
    return false;
  }

  String *val_str(String *result) override
  {
    if (require_super(current_thd))
    {
      null_value= true;
      return nullptr;
    }

    /* Serialize concurrent reload calls: viruscan_signature_stat is not
       safe to read/free/reinit from more than one thread at a time. This
       must be a separate mutex from LOCK_viruscan_engine, since
       load_engine() takes that lock itself. */
    mysql_mutex_lock(&LOCK_viruscan_reload);
    bool changed= !viruscan_signature_stat_initialized ||
                  cl_statchkdir(&viruscan_signature_stat) == 1;
    if (!changed)
      null_value= result->copy(STRING_WITH_LEN("No need to reload ClamAV engine"),
                              &my_charset_utf8mb4_general_ci);
    else if (load_engine())
      null_value= true;
    else
    {
      char message[128];
      int length= my_snprintf(message, sizeof(message),
                              "ClamAV engine reloaded with new virus database: "
                              "%lu signatures", viruscan_signatures);
      null_value= result->copy(message, length,
                              &my_charset_utf8mb4_general_ci);
      if (viruscan_signature_stat_initialized)
        cl_statfree(&viruscan_signature_stat);
      viruscan_signature_stat_initialized=
        cl_statinidir(cl_retdbdir(), &viruscan_signature_stat) == 0;
    }
    mysql_mutex_unlock(&LOCK_viruscan_reload);
    return null_value ? nullptr : result;
  }

  LEX_CSTRING func_name_cstring() const override
  {
    return "virus_reload_engine"_LEX_CSTRING;
  }

  Item *shallow_copy(THD *thd) const override
  {
    return get_item_copy<Item_func_virus_reload>(thd, this);
  }
};

class Create_func_virus_reload final : public Create_func_arg0
{
public:
  Item *create_builder(THD *thd) override
  {
    return new (thd->mem_root) Item_func_virus_reload(thd);
  }
};

static Create_func_virus_scan virus_scan_creator;
static Plugin_function virus_scan_descriptor(&virus_scan_creator);
static Create_func_virus_reload virus_reload_creator;
static Plugin_function virus_reload_descriptor(&virus_reload_creator);

static ST_FIELD_INFO viruscan_fields[]=
{
  ::Show::Column("LOGGED", ::Show::Datetime(0U), NOT_NULL),
  ::Show::Column("VIRUS", ::Show::Varchar(100), NOT_NULL),
  ::Show::Column("USER", ::Show::Varchar(32), NOT_NULL),
  ::Show::Column("HOST", ::Show::Varchar(255), NOT_NULL),
  ::Show::Column("CLAMVERSION", ::Show::Varchar(64), NOT_NULL),
  ::Show::Column("SIGNATURES", ::Show::ULong(), NOT_NULL),
  ::Show::CEnd()
};

static int viruscan_fill_table(THD *thd, TABLE_LIST *tables, COND *)
{
  TABLE *table= tables->table;
  std::array<Virus_record, VIRUS_MAX_ROWS> snapshot;
  size_t count;

  mysql_mutex_lock(&LOCK_viruscan_history);
  count= viruscan_history_size;
  for (size_t i= 0; i < count; ++i)
    snapshot[i]= viruscan_history[
      (viruscan_history_start + i) % VIRUS_MAX_ROWS];
  mysql_mutex_unlock(&LOCK_viruscan_history);

  for (size_t i= 0; i < count; ++i)
  {
    const Virus_record &record= snapshot[i];
    MYSQL_TIME logged;
    thd->variables.time_zone->gmt_sec_to_TIME(&logged, record.timestamp);
    restore_record(table, s->default_values);
    table->field[0]->store_time(&logged);
    table->field[1]->store(record.name.data(), record.name.length(),
                           system_charset_info);
    table->field[2]->store(record.user.data(), record.user.length(),
                           system_charset_info);
    table->field[3]->store(record.host.data(), record.host.length(),
                           system_charset_info);
    table->field[4]->store(record.engine.data(), record.engine.length(),
                           system_charset_info);
    table->field[5]->store(record.signatures, true);
    if (schema_table_store_record(thd, table))
      return 1;
  }
  return 0;
}

static int viruscan_table_init(void *ptr)
{
  ST_SCHEMA_TABLE *schema= static_cast<ST_SCHEMA_TABLE *>(ptr);
  schema->fields_info= viruscan_fields;
  schema->fill_table= viruscan_fill_table;
  return 0;
}

static st_mysql_information_schema viruscan_table_descriptor=
  {MYSQL_INFORMATION_SCHEMA_INTERFACE_VERSION};
static st_mysql_daemon viruscan_daemon_descriptor=
  {MYSQL_DAEMON_INTERFACE_VERSION};

static int viruscan_init(void *)
{
  mysql_mutex_register("viruscan", viruscan_mutexes,
                       array_elements(viruscan_mutexes));
  mysql_mutex_init(key_viruscan_engine, &LOCK_viruscan_engine,
                   MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_viruscan_history, &LOCK_viruscan_history,
                   MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_viruscan_reload, &LOCK_viruscan_reload,
                   MY_MUTEX_INIT_FAST);
  memset(&viruscan_signature_stat, 0, sizeof(viruscan_signature_stat));
  strmake(viruscan_clamav_version, cl_retver(),
          sizeof(viruscan_clamav_version) - 1);

  cl_error_t error= cl_init(CL_INIT_DEFAULT);
  if (error != CL_SUCCESS)
  {
    sql_print_error("viruscan: cannot initialize libclamav: %s",
                    cl_strerror(error));
    mysql_mutex_destroy(&LOCK_viruscan_reload);
    mysql_mutex_destroy(&LOCK_viruscan_history);
    mysql_mutex_destroy(&LOCK_viruscan_engine);
    return 1;
  }
  if (load_engine())
  {
    mysql_mutex_destroy(&LOCK_viruscan_reload);
    mysql_mutex_destroy(&LOCK_viruscan_history);
    mysql_mutex_destroy(&LOCK_viruscan_engine);
    return 1;
  }

  viruscan_signature_stat_initialized=
    cl_statinidir(cl_retdbdir(), &viruscan_signature_stat) == 0;
  sql_print_information("viruscan: ClamAV %s initialized",
                        viruscan_clamav_version);
  return 0;
}

static int viruscan_deinit(void *)
{
  if (viruscan_signature_stat_initialized)
    cl_statfree(&viruscan_signature_stat);
  if (viruscan_engine)
    cl_engine_free(viruscan_engine);
  viruscan_engine= nullptr;
  mysql_mutex_destroy(&LOCK_viruscan_reload);
  mysql_mutex_destroy(&LOCK_viruscan_history);
  mysql_mutex_destroy(&LOCK_viruscan_engine);
  return 0;
}

} // namespace

maria_declare_plugin(viruscan)
{
  MYSQL_DAEMON_PLUGIN,
  &viruscan_daemon_descriptor,
  "viruscan",
  "lefred",
  "ClamAV-backed virus scanning for MariaDB",
  PLUGIN_LICENSE_GPL,
  viruscan_init,
  viruscan_deinit,
  0x0100,
  viruscan_status_variables,
  nullptr,
  "1.0",
  MariaDB_PLUGIN_MATURITY_EXPERIMENTAL
},
{
  MariaDB_FUNCTION_PLUGIN,
  &virus_scan_descriptor,
  "virus_scan",
  "lefred",
  "Scan a string with ClamAV",
  PLUGIN_LICENSE_GPL,
  nullptr, nullptr, 0x0100, nullptr, nullptr, "1.0",
  MariaDB_PLUGIN_MATURITY_EXPERIMENTAL
},
{
  MariaDB_FUNCTION_PLUGIN,
  &virus_reload_descriptor,
  "virus_reload_engine",
  "lefred",
  "Reload changed ClamAV signature databases",
  PLUGIN_LICENSE_GPL,
  nullptr, nullptr, 0x0100, nullptr, nullptr, "1.0",
  MariaDB_PLUGIN_MATURITY_EXPERIMENTAL
},
{
  MYSQL_INFORMATION_SCHEMA_PLUGIN,
  &viruscan_table_descriptor,
  "VIRUSCAN_MATCHES",
  "lefred",
  "The ten most recent virus matches",
  PLUGIN_LICENSE_GPL,
  viruscan_table_init,
  nullptr,
  0x0100,
  nullptr, nullptr, "1.0",
  MariaDB_PLUGIN_MATURITY_EXPERIMENTAL
}
maria_declare_plugin_end;
