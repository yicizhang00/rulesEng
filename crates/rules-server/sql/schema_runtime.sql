-- ============================================================================
--  rulesEng v1.0 运行时物理模型（PRD §9 / FR11）
--
--  · 启动时幂等执行（全部 `CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS` 语义）
--  · 所有主键与外键严格使用 `BIGINT UNSIGNED`，与 Rust `u64` 位宽对齐
--  · `rules.mode` / `rules.status` 用 ENUM 固化四模与生命周期，杜绝脏值
--  · 引擎字符集统一 utf8mb4（规则名、拒绝理由都可能有中文与 emoji）
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 规则分组表（FR9：树状业务域）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `rule_groups` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `parent_id` BIGINT UNSIGNED NULL DEFAULT NULL,
  `name` VARCHAR(128) NOT NULL,
  `description` VARCHAR(255) NULL,
  `sort` INT NOT NULL DEFAULT 0,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_parent_name` (`parent_id`, `name`),
  CONSTRAINT `fk_groups_parent` FOREIGN KEY (`parent_id`) REFERENCES `rule_groups` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 规则主表（FR1 / FR2 / FR3 / FR11）
--
--   mode     四模：PURE（Verified 纯函数）/ STATEFUL（受限工作内存）
--                  / STREAM（流式滑动窗口）/ DMN（决策表）
--   version  语义化版本；与 name 组成唯一键，同一规则的多版本可共存
--   ast_json 四模同构 AST 的标准 JSON 序列化（画布双向转换的稳定锚点）
--   dmn_xml  仅 mode=DMN 时有值，保存原始 DMN 1.3 文档以保证第三方互通无损
--   status   上线门禁状态机：DRAFT → VERIFIED（通过 SMT 证明）→ PUBLISHED → ARCHIVED
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `rules` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `group_id` BIGINT UNSIGNED NOT NULL DEFAULT 1,
  `name` VARCHAR(128) NOT NULL,
  `mode` ENUM('PURE', 'STATEFUL', 'STREAM', 'DMN') NOT NULL DEFAULT 'PURE',
  `version` VARCHAR(32) NOT NULL DEFAULT '1.0.0',
  `entity_type` VARCHAR(64) NOT NULL DEFAULT '',
  `dsl_content` MEDIUMTEXT NOT NULL,
  `ast_json` JSON NOT NULL,
  `dmn_xml` MEDIUMTEXT NULL,
  `status` ENUM('DRAFT', 'VERIFIED', 'PUBLISHED', 'ARCHIVED') NOT NULL DEFAULT 'DRAFT',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_name_version` (`name`, `version`),
  CONSTRAINT `fk_rules_group` FOREIGN KEY (`group_id`) REFERENCES `rule_groups` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 数据源登记表（FR8）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `datasources` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(128) NOT NULL,
  `ds_type` ENUM('MYSQL', 'POSTGRESQL', 'KAFKA') NOT NULL,
  `host` VARCHAR(128) NOT NULL,
  `port` INT NOT NULL,
  `username` VARCHAR(64) NOT NULL,
  `password_enc` VARCHAR(255) NOT NULL DEFAULT '',
  `database_name` VARCHAR(128) NOT NULL DEFAULT '',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ds_name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 变量与数据源列物理绑定表（FR8：非侵入式变量映射）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `variable_bindings` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `rule_id` BIGINT UNSIGNED NOT NULL,
  `var_name` VARCHAR(64) NOT NULL,
  `datasource_id` BIGINT UNSIGNED NOT NULL,
  `table_name` VARCHAR(128) NOT NULL,
  `column_name` VARCHAR(128) NOT NULL,
  `extracted_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_rule_var` (`rule_id`, `var_name`),
  CONSTRAINT `fk_binding_rule` FOREIGN KEY (`rule_id`) REFERENCES `rules` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_binding_ds` FOREIGN KEY (`datasource_id`) REFERENCES `datasources` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 规则版本历史（FR11：版本全量落库）
--
--   每次保存（新建 / 更新）都追加一行快照，`verify_report` 保存当时的
--   分级校验报告——这正是"规则为什么被拒/被放行"的可追溯凭据。
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `rule_versions` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `rule_id` BIGINT UNSIGNED NOT NULL,
  `version` INT NOT NULL DEFAULT 1,
  `dsl_text` MEDIUMTEXT NOT NULL,
  `ast_json` JSON NULL,
  `verify_report` JSON NULL,
  `submitted_by` VARCHAR(64) NOT NULL DEFAULT '',
  `submitted_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_rule_version` (`rule_id`, `version`),
  CONSTRAINT `fk_versions_rule` FOREIGN KEY (`rule_id`) REFERENCES `rules` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 告警动作（下行通知配置；非 PRD-9 核心表，运行时保留）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `rule_actions` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `rule_id` BIGINT UNSIGNED NOT NULL,
  `action_type` VARCHAR(32) NOT NULL,
  `config` TEXT NOT NULL,
  `enabled` TINYINT(1) NOT NULL DEFAULT 1,
  `priority` INT NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_actions_rule` FOREIGN KEY (`rule_id`) REFERENCES `rules` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 触发器登记（CDC / cron；运行时保留）
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `rule_triggers` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `rule_id` BIGINT UNSIGNED NOT NULL,
  `mode` VARCHAR(16) NOT NULL,
  `cdc_table` VARCHAR(128) NULL,
  `cron_expr` VARCHAR(64) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_rule_mode` (`rule_id`, `mode`),
  CONSTRAINT `fk_triggers_rule` FOREIGN KEY (`rule_id`) REFERENCES `rules` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ---------------------------------------------------------------------------
-- 默认分组（FR9：删除分组时组内规则自动迁移到 id=1 的默认分组）
-- ---------------------------------------------------------------------------
INSERT INTO `rule_groups` (`id`, `parent_id`, `name`, `description`, `sort`)
SELECT 1, NULL, '默认分组', '未归类规则', 0
WHERE NOT EXISTS (SELECT 1 FROM `rule_groups` WHERE `id` = 1);
