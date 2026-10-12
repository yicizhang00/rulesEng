-- rulesEng 规则落库 DDL（MySQL 8.0 方言）
-- 见设计文档 §10

CREATE DATABASE IF NOT EXISTS rules_eng DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE rules_eng;

-- 数据源连接
CREATE TABLE IF NOT EXISTS datasources (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    name         VARCHAR(128) NOT NULL UNIQUE,
    db_type      VARCHAR(16)  NOT NULL COMMENT 'mysql / postgres / kafka',
    host         VARCHAR(128) NOT NULL,
    port         INT          NOT NULL,
    username     VARCHAR(64)  NOT NULL,
    password_enc VARCHAR(256) NOT NULL COMMENT 'AES 加密存储，不明文',
    schema_name  VARCHAR(128),
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (db_type IN ('mysql','postgres','kafka'))
) ENGINE=InnoDB;

-- 业务域分组
CREATE TABLE IF NOT EXISTS rule_groups (
    id   INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE
) ENGINE=InnoDB;

-- 规则主表
CREATE TABLE IF NOT EXISTS rules (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    name         VARCHAR(128) NOT NULL,
    group_id     INT,
    entity_type  VARCHAR(64) NOT NULL COMMENT 'Company / Account / Security',
    mode         VARCHAR(16) NOT NULL COMMENT 'LIFECYCLE / ONCE',
    cron         VARCHAR(64) DEFAULT NULL COMMENT 'mode=ONCE 时必填',
    status       VARCHAR(16) NOT NULL DEFAULT 'DRAFT' COMMENT 'DRAFT / ACTIVE / DISABLED',
    owner        VARCHAR(64),
    effective_at DATETIME,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_name_group (name, group_id),
    FOREIGN KEY (group_id) REFERENCES rule_groups(id) ON DELETE SET NULL,
    CHECK (mode IN ('LIFECYCLE','ONCE')),
    CHECK (status IN ('DRAFT','ACTIVE','DISABLED'))
) ENGINE=InnoDB;

-- 规则版本历史
CREATE TABLE IF NOT EXISTS rule_versions (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    rule_id       INT NOT NULL,
    version       INT NOT NULL,
    dsl_text      MEDIUMTEXT NOT NULL COMMENT '原始 DSL 文本',
    ast_json      JSON NOT NULL COMMENT '解析后的 AST',
    verify_report JSON DEFAULT NULL COMMENT 'verifier + smt 校验报告',
    diff_vs_prev  JSON DEFAULT NULL COMMENT '与上一版的语义 diff',
    submitted_by  VARCHAR(64),
    submitted_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_rule_version (rule_id, version),
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 变量绑定到数据源列
CREATE TABLE IF NOT EXISTS rule_bindings (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    rule_id       INT NOT NULL,
    var_name      VARCHAR(128) NOT NULL COMMENT 'DSL 里的变量名，例如 cancel_ratio',
    datasource_id INT,
    table_name    VARCHAR(128),
    column_name   VARCHAR(128),
    extracted_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_rule_var (rule_id, var_name),
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE,
    FOREIGN KEY (datasource_id) REFERENCES datasources(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 告警动作
CREATE TABLE IF NOT EXISTS rule_actions (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    rule_id     INT NOT NULL,
    action_type VARCHAR(32) NOT NULL COMMENT 'sms / http / email / state_transition',
    config      JSON NOT NULL COMMENT '例如 {"url":"...","method":"POST"}',
    enabled     TINYINT(1) NOT NULL DEFAULT 1,
    priority    INT NOT NULL DEFAULT 0,
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE,
    CHECK (action_type IN ('sms','http','email','state_transition'))
) ENGINE=InnoDB;

-- 触发器：LIFECYCLE 订阅 CDC 表 / ONCE 配 cron
CREATE TABLE IF NOT EXISTS rule_triggers (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    rule_id    INT NOT NULL,
    mode       VARCHAR(16) NOT NULL,
    cdc_table  VARCHAR(128) DEFAULT NULL COMMENT 'LIFECYCLE 模式：订阅的 binlog 表',
    cron_expr  VARCHAR(64)  DEFAULT NULL COMMENT 'ONCE 模式：cron 表达式',
    UNIQUE KEY uk_rule_mode (rule_id, mode),
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE,
    CHECK (mode IN ('LIFECYCLE','ONCE'))
) ENGINE=InnoDB;

-- 索引
CREATE INDEX idx_rules_status ON rules(status);
CREATE INDEX idx_bindings_rule ON rule_bindings(rule_id);
CREATE INDEX idx_versions_rule ON rule_versions(rule_id);
