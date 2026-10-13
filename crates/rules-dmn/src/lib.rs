//! # rules-dmn —— DMN 1.3 / 1.4 决策表 XML 双向映射（FR3）
//!
//! 本 crate 是「模式 D：DMN 决策表」的 **互操作层**：
//! 把 [`DecisionTableDecl`]（rulesEng 四模同构 AST 的决策表分支）
//! 与 OMG DMN 1.3 `decisionTable` XML 做**无损双向映射**，满足
//! NFR「DMN 1.3 XML 互通」。
//!
//! ## 设计取舍
//!
//! * **零外部依赖**：与项目「不引入外部 Z3 / libclang」的取向一致，
//!   内置一个极小的 XML DOM 解析器（支持 prolog / 注释 / CDATA /
//!   实体转义 / 命名空间前缀剥离），不做 DTD / XSD 校验。
//! * **单文件决策表语义对齐**：DMN 里 `inputExpression` 声明输入变量、
//!   `inputEntry` 是**一元测试**（unary test）。本 crate 导出时把
//!   [`InputEntry::Expr`] 的完整谓词写进 `inputEntry/text`（合法 DMN 1.3
//!   S-FEEL 表达式，无损）；导入时**同时接受**完整谓词与一元测试
//!   （`> 100` 会自动补上输入变量名）两种形态。
//! * **区间口径**：`[a .. b]` ↔ [`InputEntry::Range`]（闭区间）。
//!   `(a .. b)` / `[a .. b)` 等非闭区间会降维成显式比较谓词，避免静默
//!   丢失边界语义。
//! * **默认行**：DMN 无「默认行」标记，约定「全部输入项为 `-`」即默认行，
//!   与 DSL 的 `default => (...)` 一一对应。
//!
//! ## 示例
//!
//! ```text
//! use rules_ast::*;
//! use rules_dmn::{export_table, import_table};
//!
//! let t = DecisionTableDecl {
//!     name: "DetermineAmount".into(),
//!     params: vec![Param { name: "req_time".into(), ty: DataType::Timestamp }],
//!     outputs: vec![
//!         Param { name: "amount".into(), ty: DataType::Int },
//!         Param { name: "phase".into(), ty: DataType::Int },
//!     ],
//!     hit_policy: HitPolicy::Unique,
//!     rows: vec![DecisionRow {
//!         inputs: vec![InputEntry::Range {
//!             lo: Expr::Str("11-01".into()),
//!             hi: Expr::Str("11-03".into()),
//!         }],
//!         outputs: vec![Expr::Number(10.0), Expr::Ident("PHASE_1".into())],
//!         is_default: false,
//!         meta: NodeMeta::default(),
//!         span: Span::default(),
//!     }],
//!     meta: NodeMeta::default(),
//!     span: Span::default(),
//! };
//!
//! let xml = export_table(&t);
//! assert!(xml.contains("hitPolicy=\"U\""));
//! let back = import_table(&xml).unwrap();
//! assert_eq!(back.rows[0].inputs[0], t.rows[0].inputs[0]);
//! ```

use rules_ast::{
    BinaryOp, DataType, DecisionRow, DecisionTableDecl, Expr, HitPolicy, InputEntry, NodeMeta, Param,
    Span,
};

/// DMN 1.3 模型命名空间（`https://www.omg.org/spec/DMN/20191111/MODEL/`）。
pub const DMN_NS: &str = "https://www.omg.org/spec/DMN/20191111/MODEL/";

// =====================================================================
// 错误
// =====================================================================

#[derive(Debug, thiserror::Error)]
pub enum DmnError {
    /// XML 词法 / 结构错误。
    #[error("DMN XML 解析错误：{0}")]
    Xml(String),
    /// DMN 元素结构不符合预期（缺元素、缺属性等）。
    #[error("DMN 结构错误：{0}")]
    Structure(String),
    /// S-FEEL 表达式解析错误。
    #[error("S-FEEL 表达式错误：{0}")]
    Feel(String),
}

pub type Result<T> = std::result::Result<T, DmnError>;

// =====================================================================
// 极简 XML DOM
// =====================================================================

/// 解析后的 XML 元素。命名空间前缀已在解析时剥离（`dmn:decision` → `decision`）。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Xml {
    /// 本地名（已剥离 `ns:` 前缀）。
    pub name: String,
    /// 属性表（属性名同样剥离前缀）。
    pub attrs: Vec<(String, String)>,
    /// 子元素。
    pub children: Vec<Xml>,
    /// 本元素直接包含的文本（已做实体解码，保留原始空白）。
    pub text: String,
}

impl Xml {
    /// 取属性值。
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    /// 第一个名为 `name` 的直接子元素。
    pub fn child(&self, name: &str) -> Option<&Xml> {
        self.children.iter().find(|c| c.name == name)
    }

    /// 全部名为 `name` 的直接子元素。
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Xml> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// 递归收集同名后裔（不含自身）。
    pub fn descendants<'a>(&'a self, name: &str) -> Vec<&'a Xml> {
        let mut out = Vec::new();
        for c in &self.children {
            if c.name == name {
                out.push(c);
            }
            out.extend(c.descendants(name));
        }
        out
    }

    /// 递归收集同名后裔（含自身）。
    pub fn descendants_or_self<'a>(&'a self, name: &str) -> Vec<&'a Xml> {
        let mut out = Vec::new();
        if self.name == name {
            out.push(self);
        }
        out.extend(self.descendants(name));
        out
    }

    /// 本元素及其全部后裔的文本拼接。
    pub fn all_text(&self) -> String {
        let mut s = self.text.clone();
        for c in &self.children {
            s.push_str(&c.all_text());
        }
        s
    }

    /// 名为 `name` 的直接子元素的文本（去首尾空白）。
    pub fn child_text(&self, name: &str) -> Option<String> {
        self.child(name).map(|c| c.all_text().trim().to_string())
    }
}

/// 解析一段 XML 文档，返回根元素。
pub fn parse_xml(src: &str) -> Result<Xml> {
    let mut p = Xp::new(src);
    p.skip_misc()?;
    if p.eof() {
        return Err(DmnError::Xml("文档为空".into()));
    }
    if !p.starts("<") {
        return Err(DmnError::Xml("文档根位置不是元素".into()));
    }
    let root = p.parse_element()?;
    Ok(root)
}

struct Xp {
    c: Vec<char>,
    i: usize,
}

impl Xp {
    fn new(s: &str) -> Self {
        Xp { c: s.chars().collect(), i: 0 }
    }
    fn eof(&self) -> bool {
        self.i >= self.c.len()
    }
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }
    fn starts(&self, s: &str) -> bool {
        let mut k = self.i;
        for ch in s.chars() {
            if self.c.get(k) != Some(&ch) {
                return false;
            }
            k += 1;
        }
        true
    }
    fn take(&mut self, n: usize) {
        self.i = (self.i + n).min(self.c.len());
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
            self.i += 1;
        }
    }
    fn skip_until(&mut self, marker: &str) -> Result<()> {
        while !self.eof() {
            if self.starts(marker) {
                self.take(marker.chars().count());
                return Ok(());
            }
            self.i += 1;
        }
        Err(DmnError::Xml(format!("未找到结束标记 {marker:?}")))
    }
    /// prolog (`<?xml ?>`) / 注释 / DOCTYPE 等杂项。
    fn skip_misc(&mut self) -> Result<()> {
        loop {
            self.skip_ws();
            if self.starts("<?") {
                self.skip_until("?>")?;
            } else if self.starts("<!--") {
                self.skip_until("-->")?;
            } else if self.starts("<!") {
                self.skip_until(">")?;
            } else {
                return Ok(());
            }
        }
    }
    fn parse_name(&mut self) -> Result<String> {
        let start = self.i;
        while matches!(self.peek(), Some(ch) if is_name_char(ch)) {
            self.i += 1;
        }
        if self.i == start {
            return Err(DmnError::Xml(format!("位置 {} 处缺少元素/属性名", self.i)));
        }
        Ok(self.c[start..self.i].iter().collect())
    }
    fn parse_quoted(&mut self) -> Result<String> {
        let q = self
            .peek()
            .ok_or_else(|| DmnError::Xml("属性值意外结束".into()))?;
        if q != '"' && q != '\'' {
            return Err(DmnError::Xml(format!("位置 {} 处属性值缺少引号", self.i)));
        }
        self.i += 1;
        let start = self.i;
        while let Some(ch) = self.peek() {
            if ch == q {
                break;
            }
            self.i += 1;
        }
        if self.eof() {
            return Err(DmnError::Xml("属性值未闭合".into()));
        }
        let raw: String = self.c[start..self.i].iter().collect();
        self.i += 1; // 关闭引号
        Ok(decode_entities(&raw))
    }
    fn parse_element(&mut self) -> Result<Xml> {
        self.take(1); // '<'
        let raw_name = self.parse_name()?;
        let name = local_name(&raw_name).to_string();
        let mut attrs: Vec<(String, String)> = Vec::new();
        loop {
            self.skip_ws();
            if self.starts("/>") {
                self.take(2);
                return Ok(Xml { name, attrs, children: Vec::new(), text: String::new() });
            }
            if self.starts(">") {
                self.take(1);
                break;
            }
            if self.eof() {
                return Err(DmnError::Xml(format!("元素 <{name}> 未闭合")));
            }
            let an = self.parse_name()?;
            self.skip_ws();
            if !self.starts("=") {
                return Err(DmnError::Xml(format!("属性 <{name}> @{an} 缺少 '='")));
            }
            self.take(1);
            self.skip_ws();
            let av = self.parse_quoted()?;
            attrs.push((local_name(&an).to_string(), av));
        }

        let mut children: Vec<Xml> = Vec::new();
        let mut text = String::new();
        loop {
            if self.eof() {
                return Err(DmnError::Xml(format!("元素 <{name}> 未闭合")));
            }
            if self.starts("</") {
                self.take(2);
                let cn = local_name(&self.parse_name()?).to_string();
                self.skip_ws();
                if !self.starts(">") {
                    return Err(DmnError::Xml(format!("结束标签 </{cn}> 格式错误")));
                }
                self.take(1);
                if cn != name {
                    return Err(DmnError::Xml(format!("标签不匹配：<{name}> 由 </{cn}> 关闭")));
                }
                break;
            }
            if self.starts("<!--") {
                self.skip_until("-->")?;
                continue;
            }
            if self.starts("<![CDATA[") {
                self.take("<![CDATA[".chars().count());
                let start = self.i;
                self.skip_until("]]>")?;
                text.extend(self.c[start..self.i - 3].iter());
                continue;
            }
            if self.starts("<?") {
                self.skip_until("?>")?;
                continue;
            }
            if self.starts("<") {
                children.push(self.parse_element()?);
                continue;
            }
            let start = self.i;
            while !self.eof() && !self.starts("<") {
                self.i += 1;
            }
            let raw: String = self.c[start..self.i].iter().collect();
            text.push_str(&decode_entities(&raw));
        }
        Ok(Xml { name, attrs, children, text })
    }
}

fn is_name_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | ':' | '.')
}

/// 剥离命名空间前缀：`dmn:decision` → `decision`。
fn local_name(n: &str) -> &str {
    match n.rsplit_once(':') {
        Some((_, l)) => l,
        None => n,
    }
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let decoded = tail.find(';').and_then(|j| {
            let ent = &tail[1..j];
            let ch = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => ent
                    .strip_prefix("#x")
                    .or_else(|| ent.strip_prefix("#X"))
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .or_else(|| ent.strip_prefix('#').and_then(|d| d.parse::<u32>().ok()))
                    .and_then(char::from_u32),
            };
            ch.map(|c| (c, j))
        });
        match decoded {
            Some((c, j)) => {
                out.push(c);
                rest = &tail[j + 1..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// 文本 → XML 安全文本。
pub fn xml_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            _ => o.push(c),
        }
    }
    o
}

fn sanitize_id(s: &str) -> String {
    let mut o: String = s
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' { c } else { '_' })
        .collect();
    if o.is_empty() {
        o.push_str("dt");
    }
    if o.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        o.insert(0, '_');
    }
    o
}

// =====================================================================
// 类型映射
// =====================================================================

/// rulesEng [`DataType`] → DMN `typeRef`（FEEL 类型名）。
pub fn type_ref(t: DataType) -> &'static str {
    match t {
        DataType::Int => "integer",
        DataType::Float => "number",
        DataType::Bool => "boolean",
        DataType::String => "string",
        DataType::Timestamp => "date and time",
        DataType::Duration => "duration",
        DataType::BitVec => "number",
    }
}

/// DMN `typeRef` → rulesEng [`DataType`]（未知类型回落 `Float`）。
pub fn type_from_ref(s: &str) -> DataType {
    match s.trim().to_ascii_lowercase().as_str() {
        "integer" | "int" | "long" => DataType::Int,
        "boolean" | "bool" => DataType::Bool,
        "string" | "text" => DataType::String,
        "date and time" | "date" | "datetime" | "time" => DataType::Timestamp,
        "duration" | "year-month-duration" | "day-time-duration" => DataType::Duration,
        _ => DataType::Float,
    }
}

// =====================================================================
// S-FEEL 渲染
// =====================================================================

fn op_tok(op: BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Mod => "%",
        BinaryOp::Eq => "==",
        BinaryOp::Neq => "!=",
        BinaryOp::Gt => ">",
        BinaryOp::Gte => ">=",
        BinaryOp::Lt => "<",
        BinaryOp::Lte => "<=",
        BinaryOp::And => "and",
        BinaryOp::Or => "or",
        BinaryOp::BitAnd => "&",
        BinaryOp::BitOr => "|",
        BinaryOp::BitXor => "^",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
    }
}

fn fmt_num(n: f64) -> String {
    if n.is_finite() && n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// [`Expr`] → S-FEEL 文本（**全量加括号**，保证可无歧义回读）。
pub fn render_expr(e: &Expr) -> String {
    match e {
        Expr::Ident(s) => s.clone(),
        Expr::Path(p) => p.join("."),
        Expr::Number(n) => fmt_num(*n),
        Expr::Hex(h) => format!("0x{h:X}"),
        Expr::Str(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        Expr::Bool(b) => if *b { "true" } else { "false" }.to_string(),
        Expr::DurationLit(d) => format!("{}s", d.as_secs()),
        Expr::Binary { op, left, right } => {
            format!("({} {} {})", render_expr(left), op_tok(*op), render_expr(right))
        }
        Expr::UnaryNot(x) => format!("not ({})", render_expr(x)),
        Expr::Call { func, args } => format!("{func}({})", render_args(args)),
        Expr::TableLookup { table, args, index } => {
            if *index == 0 {
                format!("{table}({})", render_args(args))
            } else {
                format!("{table}[{index}]({})", render_args(args))
            }
        }
    }
}

fn render_args(args: &[Expr]) -> String {
    args.iter().map(render_expr).collect::<Vec<_>>().join(", ")
}

/// 区间端点渲染：`Str("11-01")` 这类日历/数值字面量以裸词输出，
/// 其余走 [`render_expr`]。
fn render_bound(e: &Expr) -> String {
    if let Expr::Str(s) = e {
        if looks_like_bare_literal(s) {
            return s.clone();
        }
    }
    render_expr(e)
}

/// `11-01` / `2025-11-02` / `09:30` 等日历口径裸词。
fn looks_like_bare_literal(s: &str) -> bool {
    let mut has_sep = false;
    let mut first = true;
    for c in s.chars() {
        if first {
            if !c.is_ascii_digit() {
                return false;
            }
            first = false;
            continue;
        }
        match c {
            '0'..='9' => {}
            '-' | ':' | '/' => has_sep = true,
            _ => return false,
        }
    }
    has_sep && !s.is_empty()
}

// =====================================================================
// S-FEEL 解析
// =====================================================================

/// S-FEEL（本 crate 渲染出的子集 + 常见 DMN 一元测试）→ [`Expr`]。
pub fn parse_feel(src: &str) -> Result<Expr> {
    let mut p = Feel::new(src);
    let e = p.parse_or()?;
    p.skip_ws();
    if !p.eof() {
        return Err(DmnError::Feel(format!(
            "表达式 {:?} 在 {:?} 处有多余字符",
            src,
            p.rest()
        )));
    }
    Ok(e)
}

struct Feel {
    c: Vec<char>,
    i: usize,
}

impl Feel {
    fn new(s: &str) -> Self {
        Feel { c: s.chars().collect(), i: 0 }
    }
    fn eof(&self) -> bool {
        self.i >= self.c.len()
    }
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }
    fn at(&self, k: usize) -> Option<char> {
        self.c.get(self.i + k).copied()
    }
    fn starts(&self, s: &str) -> bool {
        let mut k = self.i;
        for ch in s.chars() {
            if self.c.get(k) != Some(&ch) {
                return false;
            }
            k += 1;
        }
        true
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(c) if c.is_whitespace()) {
            self.i += 1;
        }
    }
    fn rest(&self) -> String {
        self.c[self.i..].iter().collect()
    }
    fn word_at(&self, w: &str) -> bool {
        if !self.starts(w) {
            return false;
        }
        match self.c.get(self.i + w.chars().count()) {
            None => true,
            Some(c) => !(c.is_alphanumeric() || *c == '_'),
        }
    }
    fn eat_word(&mut self, w: &str) -> bool {
        if self.word_at(w) {
            self.i += w.chars().count();
            true
        } else {
            false
        }
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut l = self.parse_and()?;
        loop {
            self.skip_ws();
            let hit = if self.starts("||") {
                self.i += 2;
                true
            } else {
                self.eat_word("or")
            };
            if !hit {
                break;
            }
            let r = self.parse_and()?;
            l = Expr::bin(BinaryOp::Or, l, r);
        }
        Ok(l)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut l = self.parse_bitor()?;
        loop {
            self.skip_ws();
            let hit = if self.starts("&&") {
                self.i += 2;
                true
            } else {
                self.eat_word("and")
            };
            if !hit {
                break;
            }
            let r = self.parse_bitor()?;
            l = Expr::bin(BinaryOp::And, l, r);
        }
        Ok(l)
    }

    fn parse_bitor(&mut self) -> Result<Expr> {
        let mut l = self.parse_bitxor()?;
        loop {
            self.skip_ws();
            if self.starts("|") && !self.starts("||") {
                self.i += 1;
                let r = self.parse_bitxor()?;
                l = Expr::bin(BinaryOp::BitOr, l, r);
            } else {
                break;
            }
        }
        Ok(l)
    }

    fn parse_bitxor(&mut self) -> Result<Expr> {
        let mut l = self.parse_bitand()?;
        loop {
            self.skip_ws();
            if self.starts("^") {
                self.i += 1;
                let r = self.parse_bitand()?;
                l = Expr::bin(BinaryOp::BitXor, l, r);
            } else {
                break;
            }
        }
        Ok(l)
    }

    fn parse_bitand(&mut self) -> Result<Expr> {
        let mut l = self.parse_cmp()?;
        loop {
            self.skip_ws();
            if self.starts("&") && !self.starts("&&") {
                self.i += 1;
                let r = self.parse_cmp()?;
                l = Expr::bin(BinaryOp::BitAnd, l, r);
            } else {
                break;
            }
        }
        Ok(l)
    }

    fn parse_cmp(&mut self) -> Result<Expr> {
        let l = self.parse_shift()?;
        self.skip_ws();
        let op = if self.starts("==") {
            Some((BinaryOp::Eq, 2))
        } else if self.starts("!=") {
            Some((BinaryOp::Neq, 2))
        } else if self.starts("<=") {
            Some((BinaryOp::Lte, 2))
        } else if self.starts(">=") {
            Some((BinaryOp::Gte, 2))
        } else if self.starts("<") {
            Some((BinaryOp::Lt, 1))
        } else if self.starts(">") {
            Some((BinaryOp::Gt, 1))
        } else if self.starts("=") {
            Some((BinaryOp::Eq, 1))
        } else {
            None
        };
        match op {
            Some((o, n)) => {
                self.i += n;
                let r = self.parse_shift()?;
                Ok(Expr::bin(o, l, r))
            }
            None => Ok(l),
        }
    }

    fn parse_shift(&mut self) -> Result<Expr> {
        let mut l = self.parse_add()?;
        loop {
            self.skip_ws();
            let op = if self.starts("<<") {
                Some(BinaryOp::Shl)
            } else if self.starts(">>") {
                Some(BinaryOp::Shr)
            } else {
                None
            };
            match op {
                Some(o) => {
                    self.i += 2;
                    let r = self.parse_add()?;
                    l = Expr::bin(o, l, r);
                }
                None => break,
            }
        }
        Ok(l)
    }

    fn parse_add(&mut self) -> Result<Expr> {
        let mut l = self.parse_mul()?;
        loop {
            self.skip_ws();
            let op = if self.starts("+") {
                Some(BinaryOp::Add)
            } else if self.starts("-") {
                Some(BinaryOp::Sub)
            } else {
                None
            };
            match op {
                Some(o) => {
                    self.i += 1;
                    let r = self.parse_mul()?;
                    l = Expr::bin(o, l, r);
                }
                None => break,
            }
        }
        Ok(l)
    }

    fn parse_mul(&mut self) -> Result<Expr> {
        let mut l = self.parse_unary()?;
        loop {
            self.skip_ws();
            let op = if self.starts("*") {
                Some(BinaryOp::Mul)
            } else if self.starts("/") {
                Some(BinaryOp::Div)
            } else if self.starts("%") {
                Some(BinaryOp::Mod)
            } else {
                None
            };
            match op {
                Some(o) => {
                    self.i += 1;
                    let r = self.parse_unary()?;
                    l = Expr::bin(o, l, r);
                }
                None => break,
            }
        }
        Ok(l)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        self.skip_ws();
        if self.starts("-") {
            self.i += 1;
            let e = self.parse_unary()?;
            // 负数字面量直接折叠，保证 `-3` ↔ Number(-3.0) 无损往返
            return Ok(match e {
                Expr::Number(n) => Expr::Number(-n),
                other => Expr::bin(BinaryOp::Sub, Expr::Number(0.0), other),
            });
        }
        if self.starts("!") && !self.starts("!=") {
            self.i += 1;
            let e = self.parse_unary()?;
            return Ok(Expr::UnaryNot(Box::new(e)));
        }
        if self.eat_word("not") {
            let e = self.parse_unary()?;
            return Ok(Expr::UnaryNot(Box::new(e)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        self.skip_ws();
        let c = self
            .peek()
            .ok_or_else(|| DmnError::Feel("表达式意外结束".into()))?;

        if c == '(' {
            self.i += 1;
            let e = self.parse_or()?;
            self.skip_ws();
            if self.peek() != Some(')') {
                return Err(DmnError::Feel("缺少 ')'".into()));
            }
            self.i += 1;
            return Ok(e);
        }

        if c == '"' || c == '\'' {
            self.i += 1;
            let mut s = String::new();
            while let Some(ch) = self.peek() {
                if ch == '\\' {
                    self.i += 1;
                    if let Some(n) = self.peek() {
                        s.push(match n {
                            'n' => '\n',
                            't' => '\t',
                            other => other,
                        });
                        self.i += 1;
                    }
                    continue;
                }
                if ch == c {
                    self.i += 1;
                    return Ok(Expr::Str(s));
                }
                s.push(ch);
                self.i += 1;
            }
            return Err(DmnError::Feel("字符串字面量未闭合".into()));
        }

        if c == '0' && matches!(self.at(1), Some('x') | Some('X')) {
            self.i += 2;
            let start = self.i;
            while matches!(self.peek(), Some(h) if h.is_ascii_hexdigit()) {
                self.i += 1;
            }
            if self.i == start {
                return Err(DmnError::Feel("0x 后缺少十六进制数字".into()));
            }
            let t: String = self.c[start..self.i].iter().collect();
            let v = u64::from_str_radix(&t, 16)
                .map_err(|e| DmnError::Feel(format!("非法十六进制 {t:?}：{e}")))?;
            return Ok(Expr::Hex(v));
        }

        if c.is_ascii_digit() || (c == '.' && matches!(self.at(1), Some(d) if d.is_ascii_digit())) {
            let start = self.i;
            while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                self.i += 1;
            }
            if self.peek() == Some('.') {
                self.i += 1;
                while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            if matches!(self.peek(), Some('e') | Some('E')) {
                let save = self.i;
                self.i += 1;
                if matches!(self.peek(), Some('+') | Some('-')) {
                    self.i += 1;
                }
                if matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                    while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                        self.i += 1;
                    }
                } else {
                    self.i = save;
                }
            }
            let t: String = self.c[start..self.i].iter().collect();
            let v: f64 = t
                .parse()
                .map_err(|e| DmnError::Feel(format!("非法数字 {t:?}：{e}")))?;
            return Ok(Expr::Number(v));
        }

        if c.is_alphabetic() || c == '_' {
            let start = self.i;
            while matches!(self.peek(), Some(ch) if ch.is_alphanumeric() || ch == '_') {
                self.i += 1;
            }
            let mut seg: Vec<String> = vec![self.c[start..self.i].iter().collect()];
            while self.peek() == Some('.')
                && matches!(self.at(1), Some(ch) if ch.is_alphanumeric() || ch == '_')
            {
                self.i += 1;
                let s2 = self.i;
                while matches!(self.peek(), Some(ch) if ch.is_alphanumeric() || ch == '_') {
                    self.i += 1;
                }
                seg.push(self.c[s2..self.i].iter().collect());
            }
            if seg.len() == 1 {
                match seg[0].to_ascii_lowercase().as_str() {
                    "true" => return Ok(Expr::Bool(true)),
                    "false" => return Ok(Expr::Bool(false)),
                    _ => {}
                }
            }
            self.skip_ws();
            if self.peek() == Some('(') {
                self.i += 1;
                let mut args: Vec<Expr> = Vec::new();
                self.skip_ws();
                if self.peek() != Some(')') {
                    loop {
                        args.push(self.parse_or()?);
                        self.skip_ws();
                        match self.peek() {
                            Some(',') => {
                                self.i += 1;
                            }
                            Some(')') => break,
                            _ => {
                                return Err(DmnError::Feel(format!(
                                    "函数实参后缺少 ',' 或 ')'，剩余 {:?}",
                                    self.rest()
                                )))
                            }
                        }
                    }
                }
                if self.peek() != Some(')') {
                    return Err(DmnError::Feel("缺少 ')'".into()));
                }
                self.i += 1;
                let func = seg.join(".");
                return Ok(Expr::Call { func, args });
            }
            if seg.len() == 1 {
                return Ok(Expr::Ident(seg[0].clone()));
            }
            return Ok(Expr::Path(seg));
        }

        Err(DmnError::Feel(format!(
            "无法解析字符 {c:?}（剩余 {:?}）",
            self.rest()
        )))
    }
}

// =====================================================================
// 导出：AST → DMN XML
// =====================================================================

/// 单表导出为完整 DMN 1.3 文档。
pub fn export_table(t: &DecisionTableDecl) -> String {
    export_tables(std::slice::from_ref(t))
}

/// 多表导出为一个 `definitions` 文档（每张表一个 `<decision>`）。
pub fn export_tables(tables: &[DecisionTableDecl]) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str(&format!(
        "<definitions xmlns=\"{DMN_NS}\" id=\"definitions_ruleseng\" name=\"rulesEng\" namespace=\"https://ruleseng.dev/dmn\">\n"
    ));
    for t in tables {
        write_decision(&mut s, t);
    }
    s.push_str("</definitions>\n");
    s
}

fn write_decision(s: &mut String, t: &DecisionTableDecl) {
    let id = sanitize_id(&t.name);
    let name = xml_escape(&t.name);
    s.push_str(&format!("  <decision id=\"decision_{id}\" name=\"{name}\">\n"));
    s.push_str(&format!(
        "    <decisionTable id=\"{id}_table\" hitPolicy=\"{}\">\n",
        t.hit_policy.dmn_code()
    ));

    for (i, p) in t.params.iter().enumerate() {
        s.push_str(&format!("      <input id=\"input_{i}\" label=\"{}\">\n", xml_escape(&p.name)));
        s.push_str(&format!(
            "        <inputExpression id=\"inputExpression_{i}\" typeRef=\"{}\">\n",
            type_ref(p.ty)
        ));
        s.push_str(&format!("          <text>{}</text>\n", xml_escape(&p.name)));
        s.push_str("        </inputExpression>\n");
        s.push_str("      </input>\n");
    }

    for (i, o) in t.outputs.iter().enumerate() {
        s.push_str(&format!(
            "      <output id=\"output_{i}\" name=\"{}\" label=\"{}\" typeRef=\"{}\"/>\n",
            xml_escape(&o.name),
            xml_escape(&o.name),
            type_ref(o.ty)
        ));
    }

    for (k, r) in t.rows.iter().enumerate() {
        let rid = format!("rule_{k}");
        s.push_str(&format!("      <rule id=\"{rid}\">\n"));
        for i in 0..t.params.len() {
            let body = if r.is_default {
                "-".to_string()
            } else {
                match r.inputs.get(i) {
                    None | Some(InputEntry::Any) => "-".to_string(),
                    Some(InputEntry::Range { lo, hi }) => {
                        format!("[{} .. {}]", render_bound(lo), render_bound(hi))
                    }
                    Some(InputEntry::Expr(e)) => render_expr(e),
                }
            };
            s.push_str(&format!(
                "        <inputEntry id=\"{rid}_in_{i}\"><text>{}</text></inputEntry>\n",
                xml_escape(&body)
            ));
        }
        for (i, o) in r.outputs.iter().enumerate() {
            s.push_str(&format!(
                "        <outputEntry id=\"{rid}_out_{i}\"><text>{}</text></outputEntry>\n",
                xml_escape(&render_expr(o))
            ));
        }
        s.push_str("      </rule>\n");
    }

    s.push_str("    </decisionTable>\n");
    s.push_str("  </decision>\n");
}

// =====================================================================
// 导入：DMN XML → AST
// =====================================================================

/// 解析 DMN 文档，返回其中**全部**决策表。
pub fn import_tables(xml: &str) -> Result<Vec<DecisionTableDecl>> {
    let root = parse_xml(xml)?;
    let mut out: Vec<DecisionTableDecl> = Vec::new();

    for d in root.descendants_or_self("decision") {
        if let Some(dt) = d.child("decisionTable") {
            let name = d
                .attr("name")
                .or_else(|| d.attr("id"))
                .map(str::to_string)
                .unwrap_or_else(|| "Decision".to_string());
            out.push(convert_table(dt, name)?);
        }
    }

    if out.is_empty() {
        for dt in root.descendants_or_self("decisionTable") {
            let fallback = dt
                .attr("id")
                .map(|s| s.strip_suffix("_table").unwrap_or(s).to_string())
                .unwrap_or_else(|| "DecisionTable".to_string());
            out.push(convert_table(dt, fallback)?);
        }
    }

    if out.is_empty() {
        return Err(DmnError::Structure("文档中未找到 <decisionTable> 元素".into()));
    }
    Ok(out)
}

/// 解析 DMN 文档，返回第一张决策表。
pub fn import_table(xml: &str) -> Result<DecisionTableDecl> {
    import_tables(xml)?
        .into_iter()
        .next()
        .ok_or_else(|| DmnError::Structure("文档中未找到 <decisionTable> 元素".into()))
}

fn convert_table(dt: &Xml, name: String) -> Result<DecisionTableDecl> {
    let hit_policy = match dt.attr("hitPolicy") {
        Some(v) => HitPolicy::parse(v)
            .ok_or_else(|| DmnError::Structure(format!("未知 hitPolicy：{v:?}")))?,
        None => HitPolicy::Unique,
    };

    let mut params: Vec<Param> = Vec::new();
    for inp in dt.children_named("input") {
        let ie = inp.child("inputExpression");
        let (pname, pty) = match ie {
            Some(ie) => {
                let nm = ie
                    .child_text("text")
                    .filter(|s| !s.is_empty())
                    .or_else(|| {
                        let t = ie.all_text();
                        let t = t.trim().to_string();
                        if t.is_empty() { None } else { Some(t) }
                    })
                    .or_else(|| inp.attr("label").map(str::to_string))
                    .ok_or_else(|| DmnError::Structure("inputExpression 缺少输入变量名".into()))?;
                let ty = ie
                    .attr("typeRef")
                    .or_else(|| inp.attr("typeRef"))
                    .map(type_from_ref)
                    .unwrap_or(DataType::Float);
                (nm, ty)
            }
            None => {
                let nm = inp
                    .attr("label")
                    .ok_or_else(|| DmnError::Structure("<input> 既无 <inputExpression> 也无 label".into()))?
                    .to_string();
                (nm, DataType::Float)
            }
        };
        params.push(Param { name: pname, ty: pty });
    }

    let mut outputs: Vec<Param> = Vec::new();
    for (i, o) in dt.children_named("output").enumerate() {
        let nm = o
            .attr("name")
            .or_else(|| o.attr("label"))
            .map(str::to_string)
            .unwrap_or_else(|| format!("output_{i}"));
        let ty = o.attr("typeRef").map(type_from_ref).unwrap_or(DataType::Float);
        outputs.push(Param { name: nm, ty });
    }

    let mut rows: Vec<DecisionRow> = Vec::new();
    for rule in dt.children_named("rule") {
        let entries: Vec<String> = rule
            .children_named("inputEntry")
            .map(|e| e.child_text("text").unwrap_or_else(|| e.all_text().trim().to_string()))
            .collect();

        let all_any = !entries.is_empty()
            && entries.iter().all(|t| {
                let t = t.trim();
                t.is_empty() || t == "-"
            });

        let inputs = if all_any {
            Vec::new()
        } else {
            let mut v: Vec<InputEntry> = Vec::new();
            for (i, raw) in entries.iter().enumerate() {
                let pname = params
                    .get(i)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| format!("in{i}"));
                v.push(convert_entry(raw, &pname)?);
            }
            v
        };

        let mut outs: Vec<Expr> = Vec::new();
        for raw in rule.children_named("outputEntry") {
            let t = raw
                .child_text("text")
                .unwrap_or_else(|| raw.all_text().trim().to_string());
            let t = t.trim();
            if t.is_empty() {
                outs.push(Expr::Number(0.0));
            } else {
                outs.push(parse_feel(t)?);
            }
        }

        rows.push(DecisionRow {
            inputs,
            outputs: outs,
            is_default: all_any,
            meta: NodeMeta::default(),
            span: Span::default(),
        });
    }

    Ok(DecisionTableDecl {
        name,
        params,
        outputs,
        hit_policy,
        rows,
        meta: NodeMeta::default(),
        span: Span::default(),
    })
}

/// DMN `inputEntry` 文本 → [`InputEntry`]。
///
/// * `-` / 空 → [`InputEntry::Any`]
/// * `[a .. b]` → [`InputEntry::Range`]（闭区间）
/// * `(a .. b)` / `[a .. b)` → 显式比较谓词
/// * `> 100`（一元测试）→ `param > 100`
/// * 其余 → 直接解析为完整谓词
fn convert_entry(text: &str, param: &str) -> Result<InputEntry> {
    let t = text.trim();
    if t.is_empty() || t == "-" {
        return Ok(InputEntry::Any);
    }
    if let Some((a, b, lo_closed, hi_closed)) = split_range(t) {
        let lo = parse_bound(a)?;
        let hi = parse_bound(b)?;
        if lo_closed && hi_closed {
            return Ok(InputEntry::Range { lo, hi });
        }
        let lo_cmp = if lo_closed { BinaryOp::Gte } else { BinaryOp::Gt };
        let hi_cmp = if hi_closed { BinaryOp::Lte } else { BinaryOp::Lt };
        let x = Expr::ident(param);
        return Ok(InputEntry::Expr(Expr::bin(
            BinaryOp::And,
            Expr::bin(lo_cmp, x.clone(), lo),
            Expr::bin(hi_cmp, x, hi),
        )));
    }
    if let Some((op, rest)) = leading_unary_test(t) {
        let rhs = parse_feel(rest)?;
        return Ok(InputEntry::Expr(Expr::bin(op, Expr::ident(param), rhs)));
    }
    Ok(InputEntry::Expr(parse_feel(t)?))
}

/// `[a .. b]` / `(a .. b]` 等 → `(lo, hi, lo_closed, hi_closed)`。
fn split_range(t: &str) -> Option<(&str, &str, bool, bool)> {
    let (lo_closed, rest) = if let Some(r) = t.strip_prefix('[') {
        (true, r)
    } else if let Some(r) = t.strip_prefix('(') {
        (false, r)
    } else {
        return None;
    };
    let (hi_closed, inner) = if let Some(r) = rest.strip_suffix(']') {
        (true, r)
    } else if let Some(r) = rest.strip_suffix(')') {
        (false, r)
    } else {
        return None;
    };
    let (a, b) = inner.split_once("..")?;
    Some((a.trim(), b.trim(), lo_closed, hi_closed))
}

/// DMN 一元测试前缀（`> 100` / `<= 5` / `= "x"`）。
fn leading_unary_test(t: &str) -> Option<(BinaryOp, &str)> {
    for (tok, op) in [
        ("<=", BinaryOp::Lte),
        (">=", BinaryOp::Gte),
        ("!=", BinaryOp::Neq),
        ("==", BinaryOp::Eq),
        ("<", BinaryOp::Lt),
        (">", BinaryOp::Gt),
        ("=", BinaryOp::Eq),
    ] {
        if let Some(rest) = t.strip_prefix(tok) {
            return Some((op, rest));
        }
    }
    None
}

fn parse_bound(t: &str) -> Result<Expr> {
    let t = t.trim();
    if t.is_empty() {
        return Err(DmnError::Feel("区间端点为空".into()));
    }
    if t.starts_with('"') || t.starts_with('\'') {
        return parse_feel(t);
    }
    if looks_like_bare_literal(t) {
        return Ok(Expr::Str(t.to_string()));
    }
    parse_feel(t)
}

// =====================================================================
// 反向：决策表 → rulesEng DSL 文本
// =====================================================================

/// 决策表渲染为 rulesEng DSL 文本（可被 `rules-parser` 无损回读）。
///
/// 产出形如：
///
/// ```text
/// decision_table DetermineAmount(req_time: timestamp) -> (amount: int, phase: int) {
///     hit_policy: UNIQUE
///     rules: [
///         in [11-01 .. 11-03] => (10, PHASE_1),
///         default => (0, 0x0)
///     ]
/// }
/// ```
pub fn render_decision_table_dsl(t: &DecisionTableDecl) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "decision_table {}({}) -> ({}) {{\n",
        t.name,
        render_params(&t.params),
        render_params(&t.outputs)
    ));
    s.push_str(&format!("    hit_policy: {}\n", t.hit_policy.as_str()));
    s.push_str("    rules: [\n");
    for (i, r) in t.rows.iter().enumerate() {
        let comma = if i + 1 == t.rows.len() { "" } else { "," };
        if r.is_default {
            s.push_str(&format!(
                "        default => ({}){}\n",
                render_list(&r.outputs),
                comma
            ));
            continue;
        }
        let entry = match r.inputs.first() {
            // DSL 没有 `-` 条目，非默认行的「任意」用恒真谓词表达（语义等价）。
            None | Some(InputEntry::Any) => "true".to_string(),
            Some(InputEntry::Range { lo, hi }) => {
                format!("in [{} .. {}]", render_dsl_bound(lo), render_dsl_bound(hi))
            }
            Some(InputEntry::Expr(e)) => render_expr(e),
        };
        s.push_str(&format!(
            "        {} => ({}){}\n",
            entry,
            render_list(&r.outputs),
            comma
        ));
    }
    s.push_str("    ]\n}\n");
    s
}

fn render_params(ps: &[Param]) -> String {
    ps.iter()
        .map(|p| format!("{}: {}", p.name, p.ty.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_list(es: &[Expr]) -> String {
    es.iter().map(render_expr).collect::<Vec<_>>().join(", ")
}

/// 区间端点：`DD-DD` 走 `date_lit` 裸词，其余按 `expr` 渲染（字符串自动加引号）。
fn render_dsl_bound(e: &Expr) -> String {
    if let Expr::Str(s) = e {
        if is_date_lit(s) {
            return s.clone();
        }
    }
    render_expr(e)
}

fn is_date_lit(s: &str) -> bool {
    let b: Vec<char> = s.chars().collect();
    b.len() == 5
        && b[0].is_ascii_digit()
        && b[1].is_ascii_digit()
        && b[2] == '-'
        && b[3].is_ascii_digit()
        && b[4].is_ascii_digit()
}

// =====================================================================
// 测试
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_table() -> DecisionTableDecl {
        DecisionTableDecl {
            name: "DetermineAmount".into(),
            params: vec![Param { name: "req_time".into(), ty: DataType::Timestamp }],
            outputs: vec![
                Param { name: "amount".into(), ty: DataType::Int },
                Param { name: "phase".into(), ty: DataType::Int },
            ],
            hit_policy: HitPolicy::Unique,
            rows: vec![
                DecisionRow {
                    inputs: vec![InputEntry::Range {
                        lo: Expr::Str("11-01".into()),
                        hi: Expr::Str("11-03".into()),
                    }],
                    outputs: vec![Expr::Number(10.0), Expr::Ident("PHASE_1".into())],
                    is_default: false,
                    meta: NodeMeta::default(),
                    span: Span::default(),
                },
                DecisionRow {
                    inputs: vec![InputEntry::Range {
                        lo: Expr::Str("11-04".into()),
                        hi: Expr::Str("11-05".into()),
                    }],
                    outputs: vec![Expr::Number(20.0), Expr::Ident("PHASE_2".into())],
                    is_default: false,
                    meta: NodeMeta::default(),
                    span: Span::default(),
                },
                DecisionRow {
                    inputs: vec![InputEntry::Expr(Expr::bin(
                        BinaryOp::Gt,
                        Expr::ident("req_time"),
                        Expr::Number(1106.0),
                    ))],
                    outputs: vec![Expr::Number(5.0), Expr::Ident("PHASE_3".into())],
                    is_default: false,
                    meta: NodeMeta::default(),
                    span: Span::default(),
                },
                DecisionRow {
                    inputs: Vec::new(),
                    outputs: vec![Expr::Number(0.0), Expr::Hex(0x00)],
                    is_default: true,
                    meta: NodeMeta::default(),
                    span: Span::default(),
                },
            ],
            meta: NodeMeta::default(),
            span: Span::default(),
        }
    }

    // ---------- XML 解析器 ----------

    #[test]
    fn xml_parser_reads_nested_tree_and_attrs() {
        let root = parse_xml(
            r#"<?xml version="1.0"?>
<!-- 注释 -->
<definitions xmlns="x" id="d1">
  <decision name="T">
    <decisionTable hitPolicy="U"><rule id="r1"/></decisionTable>
  </decision>
</definitions>"#,
        )
        .unwrap();
        assert_eq!(root.name, "definitions");
        assert_eq!(root.attr("id"), Some("d1"));
        assert_eq!(root.descendants("rule").len(), 1);
        assert_eq!(root.descendants("decisionTable")[0].attr("hitPolicy"), Some("U"));
        assert_eq!(root.descendants_or_self("definitions").len(), 1);
    }

    #[test]
    fn xml_parser_strips_namespace_prefix() {
        let root = parse_xml(r#"<dmn:definitions><dmn:decision><dmn:decisionTable hitPolicy="F"/></dmn:decision></dmn:definitions>"#).unwrap();
        assert_eq!(root.name, "definitions");
        assert_eq!(root.descendants("decisionTable")[0].attr("hitPolicy"), Some("F"));
    }

    #[test]
    fn xml_parser_decodes_entities_and_cdata() {
        let root = parse_xml(r#"<a t="x &amp; y &#65;"><text>&lt;hi&gt;</text><c><![CDATA[1 < 2 & 3]]></c></a>"#).unwrap();
        assert_eq!(root.attr("t"), Some("x & y A"));
        assert_eq!(root.child("text").unwrap().all_text().trim(), "<hi>");
        assert_eq!(root.child("c").unwrap().all_text(), "1 < 2 & 3");
    }

    #[test]
    fn xml_parser_rejects_mismatched_and_unclosed() {
        assert!(matches!(parse_xml("<a><b></a>"), Err(DmnError::Xml(_))));
        assert!(matches!(parse_xml("<a><b>"), Err(DmnError::Xml(_))));
        assert!(matches!(parse_xml(""), Err(DmnError::Xml(_))));
        assert!(matches!(parse_xml("   "), Err(DmnError::Xml(_))));
    }

    // ---------- 命中策略 ----------

    #[test]
    fn hit_policy_short_and_long_codes() {
        assert_eq!(HitPolicy::parse("U"), Some(HitPolicy::Unique));
        assert_eq!(HitPolicy::parse("first"), Some(HitPolicy::First));
        assert_eq!(HitPolicy::parse("PRIORITY"), Some(HitPolicy::Priority));
        assert_eq!(HitPolicy::parse("c"), Some(HitPolicy::Collect));
        assert_eq!(HitPolicy::Unique.dmn_code(), "U");
        assert_eq!(HitPolicy::Collect.dmn_code(), "C");
    }

    #[test]
    fn hit_policy_all_variants_round_trip() {
        for hp in [HitPolicy::Unique, HitPolicy::First, HitPolicy::Priority, HitPolicy::Collect] {
            let mut t = sample_table();
            t.hit_policy = hp;
            let xml = export_table(&t);
            assert!(xml.contains(&format!("hitPolicy=\"{}\"", hp.dmn_code())));
            let back = import_table(&xml).unwrap();
            assert_eq!(back.hit_policy, hp, "命中策略 {hp:?} 往返失败");
        }
    }

    // ---------- 往返一致性 ----------

    #[test]
    fn round_trip_preserves_decision_table() {
        let t = sample_table();
        let xml = export_table(&t);
        let back = import_table(&xml).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn round_trip_preserves_multiple_tables() {
        let mut a = sample_table();
        a.name = "TableA".into();
        a.hit_policy = HitPolicy::First;
        let mut b = sample_table();
        b.name = "TableB".into();
        b.hit_policy = HitPolicy::Collect;

        let xml = export_tables(&[a.clone(), b.clone()]);
        let back = import_tables(&xml).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0], a);
        assert_eq!(back[1], b);
    }

    #[test]
    fn exported_xml_mentions_dmn_namespace_and_decision() {
        let xml = export_table(&sample_table());
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains(DMN_NS));
        assert!(xml.contains("<decision id=\"decision_DetermineAmount\" name=\"DetermineAmount\">"));
        assert!(xml.contains("<inputExpression id=\"inputExpression_0\" typeRef=\"date and time\">"));
        assert!(xml.contains("<output id=\"output_0\" name=\"amount\""));
    }

    #[test]
    fn range_entries_render_unquoted_calendar_literals() {
        let xml = export_table(&sample_table());
        assert!(xml.contains("[11-01 .. 11-03]"), "未按期日口径渲染：{xml}");
        assert!(!xml.contains("\"11-01\""), "区间端点不应带引号：{xml}");
    }

    #[test]
    fn default_row_renders_as_dash_row() {
        let xml = export_table(&sample_table());
        assert!(xml.contains("<inputEntry id=\"rule_3_in_0\"><text>-</text></inputEntry>"));
        let back = import_table(&xml).unwrap();
        let d = back.default_row().expect("默认行丢失");
        assert!(d.inputs.is_empty());
    }

    #[test]
    fn export_escapes_xml_special_chars() {
        let mut t = sample_table();
        t.name = "A&B<C".into();
        t.outputs[0].name = "a<b".into();
        let xml = export_table(&t);
        assert!(xml.contains("A&amp;B&lt;C"), "{xml}");
        assert!(!xml.contains("A&B<C"));
        let back = import_table(&xml).unwrap();
        assert_eq!(back.name, "A&B<C");
        assert_eq!(back.outputs[0].name, "a<b");
    }

    #[test]
    fn sanitize_id_handles_odd_names() {
        assert_eq!(sanitize_id("My Table!"), "My_Table_");
        assert_eq!(sanitize_id("9lives"), "_9lives");
        assert_eq!(sanitize_id(""), "dt");
    }

    // ---------- 类型映射 ----------

    #[test]
    fn typeref_round_trips_for_all_data_types() {
        for ty in [
            DataType::Int,
            DataType::Float,
            DataType::Bool,
            DataType::String,
            DataType::Timestamp,
            DataType::Duration,
            DataType::BitVec,
        ] {
            let r = type_ref(ty);
            let back = type_from_ref(r);
            if ty == DataType::BitVec {
                // 位向量无 DMN 原生类型，约定降为 number
                assert_eq!(back, DataType::Float);
            } else {
                assert_eq!(back, ty, "类型 {ty:?} 经 {r:?} 往返失败");
            }
        }
    }

    // ---------- 一元测试 / 非闭区间 ----------

    #[test]
    fn unary_test_gets_param_prefix() {
        let e = convert_entry("> 100", "amount").unwrap();
        assert_eq!(
            e,
            InputEntry::Expr(Expr::bin(
                BinaryOp::Gt,
                Expr::ident("amount"),
                Expr::Number(100.0)
            ))
        );
    }

    #[test]
    fn non_closed_range_degrades_to_comparisons() {
        let e = convert_entry("(10 .. 20]", "x").unwrap();
        let want = InputEntry::Expr(Expr::bin(
            BinaryOp::And,
            Expr::bin(BinaryOp::Gt, Expr::ident("x"), Expr::Number(10.0)),
            Expr::bin(BinaryOp::Lte, Expr::ident("x"), Expr::Number(20.0)),
        ));
        assert_eq!(e, want);
    }

    #[test]
    fn closed_range_heightens_to_range_entry() {
        assert_eq!(
            convert_entry("[11-01 .. 11-03]", "t").unwrap(),
            InputEntry::Range {
                lo: Expr::Str("11-01".into()),
                hi: Expr::Str("11-03".into())
            }
        );
    }

    #[test]
    fn empty_and_dash_entries_are_any() {
        assert_eq!(convert_entry("-", "x").unwrap(), InputEntry::Any);
        assert_eq!(convert_entry("   ", "x").unwrap(), InputEntry::Any);
    }

    // ---------- S-FEEL ----------

    #[test]
    fn feel_round_trips_arithmetic_and_logic() {
        let samples = vec![
            Expr::bin(
                BinaryOp::Gt,
                Expr::bin(
                    BinaryOp::Add,
                    Expr::ident("a"),
                    Expr::Number(2.0),
                ),
                Expr::Number(10.0),
            ),
            Expr::bin(
                BinaryOp::And,
                Expr::bin(BinaryOp::Eq, Expr::ident("state"), Expr::Hex(0x05)),
                Expr::UnaryNot(Box::new(Expr::Bool(true))),
            ),
            Expr::Call {
                func: "abs".into(),
                args: vec![Expr::Number(-3.0), Expr::Str("x".into())],
            },
            Expr::Path(vec!["event".into(), "timestamp".into()]),
        ];
        for e in samples {
            let text = render_expr(&e);
            let back = parse_feel(&text).unwrap();
            assert_eq!(back, e, "S-FEEL 往返失败：{text}");
        }
    }

    #[test]
    fn feel_parses_hex_and_escaped_strings() {
        assert_eq!(parse_feel("0xFF").unwrap(), Expr::Hex(255));
        assert_eq!(parse_feel(r#""a\"b""#).unwrap(), Expr::Str("a\"b".into()));
        assert_eq!(
            parse_feel("1.5e2").unwrap(),
            Expr::Number(150.0)
        );
    }

    #[test]
    fn feel_rejects_trailing_garbage() {
        assert!(matches!(parse_feel("1 + 2 )"), Err(DmnError::Feel(_))));
        assert!(matches!(parse_feel(""), Err(DmnError::Feel(_))));
    }

    #[test]
    fn feel_bitops_do_not_eat_logical_ops() {
        assert_eq!(
            parse_feel("a | b").unwrap(),
            Expr::bin(BinaryOp::BitOr, Expr::ident("a"), Expr::ident("b"))
        );
        assert_eq!(
            parse_feel("a || b").unwrap(),
            Expr::bin(BinaryOp::Or, Expr::ident("a"), Expr::ident("b"))
        );
        assert_eq!(
            parse_feel("a & b").unwrap(),
            Expr::bin(BinaryOp::BitAnd, Expr::ident("a"), Expr::ident("b"))
        );
    }

    // ---------- 导入健壮性 ----------

    #[test]
    fn import_rejects_document_without_table() {
        assert!(matches!(
            import_tables("<definitions><decision/></definitions>"),
            Err(DmnError::Structure(_))
        ));
    }

    #[test]
    fn import_accepts_bare_decision_table_root() {
        let xml = r#"<decisionTable id="MyTable_table" hitPolicy="F">
            <input><inputExpression typeRef="number"><text>score</text></inputExpression></input>
            <output name="grade" typeRef="string"/>
            <rule>
                <inputEntry><text>&gt;= 90</text></inputEntry>
                <outputEntry><text>"A"</text></outputEntry>
            </rule>
        </decisionTable>"#;
        let t = import_table(xml).unwrap();
        assert_eq!(t.name, "MyTable");
        assert_eq!(t.hit_policy, HitPolicy::First);
        assert_eq!(t.params[0].name, "score");
        assert_eq!(t.params[0].ty, DataType::Float);
        assert_eq!(t.outputs[0].name, "grade");
        assert_eq!(t.outputs[0].ty, DataType::String);
        assert_eq!(
            t.rows[0].inputs[0],
            InputEntry::Expr(Expr::bin(
                BinaryOp::Gte,
                Expr::ident("score"),
                Expr::Number(90.0)
            ))
        );
        assert_eq!(t.rows[0].outputs[0], Expr::Str("A".into()));
    }

    #[test]
    fn import_rejects_unknown_hit_policy() {
        assert!(matches!(
            import_tables(r#"<decisionTable hitPolicy="Z"><rule/></decisionTable>"#),
            Err(DmnError::Structure(_))
        ));
    }

    #[test]
    fn import_reads_decision_name_from_parent() {
        let xml = r#"<definitions><decision id="dc1" name="RealName"><decisionTable id="t"/></decision></definitions>"#;
        assert_eq!(import_table(xml).unwrap().name, "RealName");
    }

    #[test]
    fn import_falls_back_to_id_without_decision_parent() {
        let xml = r#"<definitions><decisionTable id="Inner_table"/></definitions>"#;
        assert_eq!(import_table(xml).unwrap().name, "Inner");
    }

    // ---------- 文档示例（对应 crate 头部 ```text 片段） ----------

    #[test]
    fn doc_example_export_then_import() {
        let t = DecisionTableDecl {
            name: "DetermineAmount".into(),
            params: vec![Param { name: "req_time".into(), ty: DataType::Timestamp }],
            outputs: vec![
                Param { name: "amount".into(), ty: DataType::Int },
                Param { name: "phase".into(), ty: DataType::Int },
            ],
            hit_policy: HitPolicy::Unique,
            rows: vec![DecisionRow {
                inputs: vec![InputEntry::Range {
                    lo: Expr::Str("11-01".into()),
                    hi: Expr::Str("11-03".into()),
                }],
                outputs: vec![Expr::Number(10.0), Expr::Ident("PHASE_1".into())],
                is_default: false,
                meta: NodeMeta::default(),
                span: Span::default(),
            }],
            meta: NodeMeta::default(),
            span: Span::default(),
        };

        let xml = export_table(&t);
        assert!(xml.contains("hitPolicy=\"U\""));
        let back = import_table(&xml).unwrap();
        assert_eq!(back.rows[0].inputs[0], t.rows[0].inputs[0]);
        assert_eq!(back, t);
    }

    // ---------- DSL 反向渲染 ----------

    #[test]
    fn dsl_renderer_emits_parseable_text() {
        let t = sample_table();
        let dsl = render_decision_table_dsl(&t);
        assert!(dsl.contains("decision_table DetermineAmount(req_time: timestamp) -> (amount: int, phase: int) {"));
        assert!(dsl.contains("hit_policy: UNIQUE"));
        assert!(dsl.contains("in [11-01 .. 11-03] => (10, PHASE_1),"));
        assert!(dsl.contains("default => (0, 0x0)"));
        assert!(dsl.ends_with("}\n"));
    }

    #[test]
    fn dsl_renderer_round_trips_through_parser() {
        let t = sample_table();
        let dsl = render_decision_table_dsl(&t);
        let spec = rules_parser::parse(&dsl).expect("DSL 渲染结果无法被 parser 回读");
        assert_eq!(spec.decision_tables.len(), 1);
        let back = &spec.decision_tables[0];
        assert_eq!(back.name, t.name);
        assert_eq!(back.hit_policy, t.hit_policy);
        assert_eq!(back.params, t.params);
        assert_eq!(back.outputs, t.outputs);
        assert_eq!(back.rows.len(), t.rows.len());
        for (a, b) in back.rows.iter().zip(t.rows.iter()) {
            assert_eq!(a.is_default, b.is_default);
            assert_eq!(a.inputs, b.inputs, "输入项 DSL 往返不一致");
            assert_eq!(a.outputs, b.outputs, "输出项 DSL 往返不一致");
        }
    }

    #[test]
    fn xml_dsl_xml_chain_is_stable() {
        let t = sample_table();
        let xml1 = export_table(&t);
        let dsl = render_decision_table_dsl(&import_table(&xml1).unwrap());
        let t2 = rules_parser::parse(&dsl).unwrap().decision_tables.remove(0);
        let xml2 = export_table(&t2);
        assert_eq!(xml1, xml2, "XML→DSL→XML 链路不稳定");
    }

    #[test]
    fn non_date_bounds_are_quoted_in_dsl() {
        let mut t = sample_table();
        t.rows[0].inputs = vec![InputEntry::Range {
            lo: Expr::Str("2025-11-01".into()),
            hi: Expr::Str("2025-11-30".into()),
        }];
        let dsl = render_decision_table_dsl(&t);
        assert!(dsl.contains(r#"in ["2025-11-01" .. "2025-11-30"]"#), "{dsl}");
        let back = rules_parser::parse(&dsl).unwrap().decision_tables.remove(0);
        assert_eq!(back.rows[0].inputs[0], t.rows[0].inputs[0]);
    }

    // ---------- 与 parser 联动 ----------

    #[test]
    fn real_rules_file_decision_table_survives_dmn_round_trip() {
        let src = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/ecommerce_coupon.rules"),
        )
        .expect("读取 examples/ecommerce_coupon.rules 失败");
        let spec = rules_parser::parse(&src).expect("解析用例 3 失败");
        assert_eq!(spec.decision_tables.len(), 1);
        let dt = &spec.decision_tables[0];

        let xml = export_table(dt);
        let back = import_table(&xml).unwrap();
        assert_eq!(back.name, dt.name);
        assert_eq!(back.hit_policy, dt.hit_policy);
        assert_eq!(back.params, dt.params);
        assert_eq!(back.outputs, dt.outputs);
        assert_eq!(back.rows.len(), dt.rows.len());
        assert_eq!(back.default_row().is_some(), dt.default_row().is_some());
        for (a, b) in back.rows.iter().zip(dt.rows.iter()) {
            assert_eq!(a.is_default, b.is_default);
            assert_eq!(a.inputs, b.inputs, "输入项不一致（表 {:?}）", dt.name);
            assert_eq!(a.outputs, b.outputs, "输出项不一致（表 {:?}）", dt.name);
        }
    }
}
