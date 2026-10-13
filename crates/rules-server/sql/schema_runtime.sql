-- 运行时自动建表（rules-server 启动时执行，幂等）
-- 主键/外键统一 BIGINT UNSIGNED，与 Rust u64 映射一致

-- 业务域分组（支持层级：父分组 / 子分组）
CREATE TABLE IF NOT EXISTS rule_groups (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  parent_id   BIGINT UNSIGNED DEFAULT NULL,
  name        VARCHAR(128) NOT NULL,
  description VARCHAR(512) DEFAULT '',
  sort        INT NOT NULL DEFAULT 0,
  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_parent_name (parent_id, name),
  FOREIGN KEY (parent_id) REFERENCES rule_groups(id) ON DELETE SET NULL
);

-- 内置默认分组（首次启动时若空则插入）
INSERT INTO rule_groups (id, parent_id, name, description, sort)
SELECT 1, NULL, '默认分组', '未归类规则', 0
WHERE NOT EXISTS (SELECT 1 FROM rule_groups WHERE id = 1);

-- 规则主表
CREATE TABLE IF NOT EXISTS rules (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name         VARCHAR(128) NOT NULL,
  group_id     BIGINT UNSIGNED DEFAULT 1,
  entity_type  VARCHAR(64) DEFAULT '',
  dsl          MEDIUMTEXT,
  mode         VARCHAR(32) NOT NULL DEFAULT 'LIFECYCLE',
  cron         VARCHAR(64) DEFAULT NULL,
  status       VARCHAR(16) NOT NULL DEFAULT 'DRAFT',
  owner        VARCHAR(64) DEFAULT '',
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_name_group (name, group_id),
  FOREIGN KEY (group_id) REFERENCES rule_groups(id) ON DELETE SET NULL
);

-- 数据源连接
CREATE TABLE IF NOT EXISTS datasources (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name         VARCHAR(128) NOT NULL UNIQUE,
  db_type      VARCHAR(16)  NOT NULL DEFAULT 'mysql',
  host         VARCHAR(128) NOT NULL,
  port         INT UNSIGNED NOT NULL,
  username     VARCHAR(64)  NOT NULL,
  password_enc VARCHAR(256) DEFAULT '',
  schema_name  VARCHAR(128),
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 规则版本历史
CREATE TABLE IF NOT EXISTS rule_versions (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  rule_id       BIGINT UNSIGNED NOT NULL,
  version       INT NOT NULL,
  dsl_text      MEDIUMTEXT NOT NULL,
  ast_json      JSON,
  verify_report JSON,
  submitted_by  VARCHAR(64),
  submitted_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_rule_version (rule_id, version),
  FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
);

-- 变量绑定到数据源列
CREATE TABLE IF NOT EXISTS rule_bindings (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  rule_id       BIGINT UNSIGNED NOT NULL,
  var_name      VARCHAR(128) NOT NULL,
  datasource_id BIGINT UNSIGNED,
  table_name    VARCHAR(128),
  column_name   VARCHAR(128),
  extracted_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_rule_var (rule_id, var_name),
  FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE,
  FOREIGN KEY (datasource_id) REFERENCES datasources(id) ON DELETE SET NULL
);

-- 告警动作
CREATE TABLE IF NOT EXISTS rule_actions (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  rule_id     BIGINT UNSIGNED NOT NULL,
  action_type VARCHAR(32) NOT NULL,
  config      TEXT NOT NULL,
  enabled     TINYINT(1) NOT NULL DEFAULT 1,
  priority    INT NOT NULL DEFAULT 0,
  FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
);

-- 触发器
CREATE TABLE IF NOT EXISTS rule_triggers (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  rule_id    BIGINT UNSIGNED NOT NULL,
  mode       VARCHAR(16) NOT NULL,
  cdc_table  VARCHAR(128) DEFAULT NULL,
  cron_expr  VARCHAR(64)  DEFAULT NULL,
  UNIQUE KEY uk_rule_mode (rule_id, mode),
  FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
);

-- 索引（若已存在会报错，启动时代码忽略错误）
CREATE INDEX idx_rules_group ON rules(group_id);
CREATE INDEX idx_rules_status ON rules(status);
CREATE INDEX idx_bindings_rule ON rule_bindings(rule_id);
CREATE INDEX idx_versions_rule ON rule_versions(rule_id);
