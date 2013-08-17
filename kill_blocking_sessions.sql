BEGIN
   FOR c_session IN (  SELECT   a.sid, b.serial#
                         FROM   v$lock a, v$session b
                        WHERE   a.block = 1 AND a.sid = b.sid
                     ORDER BY   1)
   LOOP
      EXECUTE IMMEDIATE 'alter system kill session ''' || c_session.sid || ',' || c_session.serial# || '''';
   END LOOP;
END;
/

EXIT;

