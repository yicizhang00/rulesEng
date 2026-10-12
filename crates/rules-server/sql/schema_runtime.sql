-- 运行时自动建表（rules-server 启动时执行，幂等）
CREATE TABLE IF NOT EXISTS rules (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  group_name VARCHAR(128) DEFAULT 'default',
  dsl MEDIUMTEXT,
  mode VARCHAR(32) DEFAULT 'LIFECYCLE',
  cron VARCHAR(64)
);
CREATE TABLE IF NOT EXISTS datasources (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(128), db_type VARCHAR(32), host VARCHAR(128),
  port INT, username VARCHAR(64), schema_name VARCHAR(128)
);
CREATE TABLE IF NOT EXISTS rule_bindings (
  id INT AUTO_INCREMENT PRIMARY KEY,
  rule_id INT, var_name VARCHAR(128), datasource_id INT,
  table_name VARCHAR(128), column_name VARCHAR(128)
);
CREATE TABLE IF NOT EXISTS rule_actions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  rule_id INT, action_type VARCHAR(32), config TEXT
);
