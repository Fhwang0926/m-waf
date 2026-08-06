ALTER TABLE policy_deployments
  MODIFY COLUMN requested_by CHAR(36) NULL;
