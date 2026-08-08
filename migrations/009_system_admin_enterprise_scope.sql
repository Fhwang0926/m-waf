SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='admin_users' AND CONSTRAINT_NAME='chk_admin_users_scope'),
  'ALTER TABLE admin_users DROP CONSTRAINT chk_admin_users_scope',
  'DO 0'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

INSERT INTO enterprises(id,name,status,created_by)
SELECT UUID(),CONCAT('M-WAF 시스템 운영 ',LEFT(REPLACE(u.id,'-',''),8)),'ACTIVE',u.id
FROM admin_users u
WHERE u.role='system_admin' AND u.enterprise_id IS NULL
  AND NOT EXISTS (
    SELECT 1 FROM enterprises e
    WHERE e.created_by=u.id AND e.name=CONCAT('M-WAF 시스템 운영 ',LEFT(REPLACE(u.id,'-',''),8))
  );

UPDATE admin_users u
JOIN enterprises e ON e.created_by=u.id
  AND e.name=CONCAT('M-WAF 시스템 운영 ',LEFT(REPLACE(u.id,'-',''),8))
SET u.enterprise_id=e.id
WHERE u.role='system_admin' AND u.enterprise_id IS NULL;

ALTER TABLE admin_users
  MODIFY enterprise_id CHAR(36) NOT NULL;
