# mariadb-plugin-viruscan

![mariabd-plugin-viruscan](logo/viruscan.png)

`viruscan` plugin for MariaDB Server.

It provides:

- `VIRUS_SCAN(value)`, which scans binary-safe string data with ClamAV;
- `VIRUS_RELOAD_ENGINE()`, which reloads the engine after the signature database changes;
- the global status variables `Viruscan_clamav_signatures`,
  `Viruscan_clamav_engine_version`, and `Viruscan_virus_found`;
- `INFORMATION_SCHEMA.VIRUSCAN_MATCHES`, containing the ten most recent
  detections.

## Build

Install the libclamav development package, configure MariaDB Server with this directory at `plugin/viruscan`, and build the `viruscan` target:

```sh
cmake --build <build-directory> --target viruscan
```

If this repository is outside the server tree, link it into `plugin/viruscan` before configuring MariaDB.

## Install and use

```sql
INSTALL SONAME 'viruscan';

SELECT plugin_name, plugin_type, plugin_library, plugin_description, plugin_author 
FROM information_schema.PLUGINS WHERE plugin_library LIKE 'viruscan.so';
+---------------------+--------------------+----------------+-------------------------------------------+---------------+
| plugin_name         | plugin_type        | plugin_library | plugin_description                        | plugin_author |
+---------------------+--------------------+----------------+-------------------------------------------+---------------+
| viruscan            | DAEMON             | viruscan.so    | ClamAV-backed virus scanning for MariaDB  | lefred        |
| virus_scan          | FUNCTION           | viruscan.so    | Scan a string with ClamAV                 | lefred        |
| virus_reload_engine | FUNCTION           | viruscan.so    | Reload changed ClamAV signature databases | lefred        |
| VIRUSCAN_MATCHES    | INFORMATION SCHEMA | viruscan.so    | The ten most recent virus matches         | lefred        |
+---------------------+--------------------+----------------+-------------------------------------------+---------------+

SELECT VIRUS_SCAN('some data');
SELECT VIRUS_RELOAD_ENGINE();
SHOW GLOBAL STATUS LIKE 'Viruscan%';
SELECT * FROM INFORMATION_SCHEMA.VIRUSCAN_MATCHES;
```

Both functions require the global `SUPER` privilege. MySQL component dynamic privileges are not available through MariaDB's plugin API, so `SUPER` is the MariaDB equivalent used by this port.

ClamAV must have a readable signature database in its default database directory. Run `freshclam` before installing the plugin if the database is missing.

## Test it with Eicar

```sql 
show global status like 'viru%';
+--------------------------------+---------+
| Variable_name                  | Value   |
+--------------------------------+---------+
| Viruscan_clamav_signatures     | 3627691 |
| Viruscan_clamav_engine_version | 1.4.5   |
| Viruscan_virus_found           | 0       |
+--------------------------------+---------+
3 rows in set (0.000 sec)

SELECT VIRUS_SCAN('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*') AS scan_result;
+-----------------+
| scan_result     |
+-----------------+
| Eicar-Signature |
+-----------------+
1 row in set (0.009 sec)

show global status like 'viru%';
+--------------------------------+---------+
| Variable_name                  | Value   |
+--------------------------------+---------+
| Viruscan_clamav_signatures     | 3627691 |
| Viruscan_clamav_engine_version | 1.4.5   |
| Viruscan_virus_found           | 1       |
+--------------------------------+---------+
3 rows in set (0.001 sec)


select * from information_schema.VIRUSCAN_MATCHES;
+---------------------+-----------------+------+-----------+-------------+------------+
| LOGGED              | VIRUS           | USER | HOST      | CLAMVERSION | SIGNATURES |
+---------------------+-----------------+------+-----------+-------------+------------+
| 2026-07-27 17:40:39 | Eicar-Signature | root | localhost | 1.4.5       |    3627691 |
+---------------------+-----------------+------+-----------+-------------+------------+
1 row in set (0.001 sec)
```


## Reloading the Virus database (signatures)

```shell
$ sudo freshclam
ClamAV update process started at Mon Jul 27 18:29:39 2026
daily database available for update (local version: 27945, remote version: 28074)
Current database is 129 versions behind.
Downloading database patch # 27946...
WARNING: downloadFile: file not found: https://database.clamav.net/daily-27946.cdiff
WARNING: downloadPatch: Can't download daily-27946.cdiff from https://database.clamav.net/daily-27946.cdiff
Downloading database patch # 27946...
WARNING: downloadFile: file not found: https://database.clamav.net/daily-27946.cdiff
WARNING: downloadPatch: Can't download daily-27946.cdiff from https://database.clamav.net/daily-27946.cdiff
Downloading database patch # 27946...
WARNING: downloadFile: file not found: https://database.clamav.net/daily-27946.cdiff
WARNING: downloadPatch: Can't download daily-27946.cdiff from https://database.clamav.net/daily-27946.cdiff
WARNING: Incremental update failed, trying to download daily.cvd
Time:    3.3s, ETA:    0.0s [========================>]   22.34MiB/22.34MiB
Testing database: '/var/lib/clamav/tmp.244dc0b191/clamav-be5a0d357005a484e29db168f27685a1.tmp-daily.cvd' ...
Database test passed.
daily.cvd updated (version: 28074, sigs: 355575, f-level: 90, builder: svc.clamav-publisher)
main.cld database is up-to-date (version: 63, sigs: 3287027, f-level: 90, builder: tomjudge)
bytecode.cld database is up-to-date (version: 339, sigs: 80, f-level: 90, builder: nrandolp)
```

Then in MariaDB client:

```sql 
select virus_reload_engine();
+--------------------------------------------------------------------+
| virus_reload_engine()                                              |
+--------------------------------------------------------------------+
| ClamAV engine reloaded with new virus database: 3627981 signatures |
+--------------------------------------------------------------------+
1 row in set (6.765 sec)

show global status like 'viru%'signatures;
+--------------------------------+---------+
| Variable_name                  | Value   |
+--------------------------------+---------+
| Viruscan_clamav_signatures     | 3627981 |
+--------------------------------+---------+
1 rows in set (0.002 sec)
```

## Error log messages


These are the messages in error log during the load of the plugin:

```
2026-07-27 17:38:27 4 [Warning] Plugin 'viruscan' is of maturity level experimental while the server is alpha
2026-07-27 17:38:27 4 [Warning] Plugin 'virus_scan' is of maturity level experimental while the server is alpha
2026-07-27 17:38:27 4 [Warning] Plugin 'virus_reload_engine' is of maturity level experimental while the server is alpha
2026-07-27 17:38:27 4 [Warning] Plugin 'VIRUSCAN_MATCHES' is of maturity level experimental while the server is alpha
LibClamAV Warning: **************************************************
LibClamAV Warning: ***  The virus database is older than 7 days!  ***
LibClamAV Warning: ***   Please update it as soon as possible.    ***
LibClamAV Warning: **************************************************
2026-07-27 17:38:33 4 [Note] viruscan: loaded 3627691 signatures from /var/lib/clamav
2026-07-27 17:38:33 4 [Note] viruscan: ClamAV 1.4.5 initialized
```

When a virus is found:

```
2026-07-27 17:40:39 4 [Note] viruscan: virus found: Eicar-Signature
```

When the signature is updated (`freshclam`):

```
2026-07-27 18:30:57 4 [Note] viruscan: loaded 3627981 signatures from /var/lib/clamav
```
