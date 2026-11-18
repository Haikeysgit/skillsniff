//! JavaScript and TypeScript facts from tree-sitter-javascript and
//! tree-sitter-typescript trees.
//!
//! The same walk serves both grammars: one query pass collects identifiers,
//! member expressions, strings, calls and binding forms in document order; a
//! second step resolves `require`/`import` aliases, classifies sites and turns
//! byte ranges into the identifiers and site ids they reference.
//!
//! JavaScript private names (`#field`) would read like internal site ids
//! (`#s1`, `#c1`, `#p1`), so they are rewritten to `%field`, which is neither
//! a site id nor a valid JavaScript identifier.

use std::collections::HashSet;
use std::sync::OnceLock;

use tree_sitter::{Language, Node, Query, Tree};

use super::common::{
    Bind, Call, Core, MAX_FOLD_NODES, MAX_NAME_SEGMENTS, TEXT_CHARS, last_segment, line, run_query,
};
use super::patterns::{
    DOWNLOAD_EXEC, ENV_LAUNCHERS, EVAL, EXEC, NETWORK, REVERSE_SHELL, SENSITIVE_WRITE, SHELL_FLAGS,
    SHELLS, UNKNOWN_PIECE, env_class, is_sensitive_write_path, literal_source_class,
    normalize_path, pipes_download_to_shell,
};
use super::taint::{Facts, Site};
use super::{LangRules, clip};

const QUERY_COMMON: &str = r#"
(identifier) @ident
(shorthand_property_identifier) @ident
(member_expression) @member
(subscript_expression) @member
(string) @str
(template_string) @str
(binary_expression) @binop
(call_expression) @call
(new_expression) @call
(variable_declarator) @decl
(assignment_expression) @assign
(augmented_assignment_expression) @augassign
(for_in_statement) @for
(function_declaration) @func
(generator_function_declaration) @func
(function_expression) @func
(arrow_function) @func
(method_definition) @func
(return_statement) @return
(import_statement) @import
"#;
const QUERY_JS: &str = "(field_definition) @field";
const QUERY_TS: &str = "(public_field_definition) @field";

/// Request methods of `axios`, `got` and their instances.
const HTTP_VERBS: &[&str] = &[
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "head",
    "options",
    "request",
    "stream",
    "postForm",
    "putForm",
    "patchForm",
];
const EXEC_FUNCS: &[&str] = &[
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "execFile",
    "execFileSync",
    "fork",
];
/// Constructors whose result is a network client: after `s = <ctor>(...)`,
/// `s.write(...)` resolves to `<ctor>().write(...)`. A `fetch` response is
/// not a client.
const CLIENT_CONSTRUCTORS: &[&str] = &[
    "http.request",
    "http.get",
    "https.request",
    "https.get",
    "net.Socket",
    "net.connect",
    "net.createConnection",
    "tls.connect",
    "tls.TLSSocket",
    "WebSocket",
    "ws",
    "ws.WebSocket",
    "XMLHttpRequest",
    "axios.create",
    "got.extend",
];
const PATH_BUILDERS: &[&str] = &[
    "path.join",
    "path.resolve",
    "path.normalize",
    "path.posix.join",
    "path.posix.resolve",
    "path.win32.join",
    "path.win32.resolve",
];
/// Names whose aliases are worth following: `const e = process.env`,
/// `const run = eval`, `const { exec } = cp`.
const KNOWN_ROOTS: &[&str] = &[
    "child_process",
    "fs",
    "http",
    "https",
    "net",
    "tls",
    "vm",
    "os",
    "path",
    "process",
    "axios",
    "node-fetch",
    "undici",
    "got",
    "ws",
    "zx",
    "fetch",
    "eval",
    "Function",
    "WebSocket",
    "XMLHttpRequest",
    "Deno",
    "Bun",
    "require",
    "module",
    "globalThis",
    "window",
    "global",
    "self",
    "setTimeout",
    "setInterval",
];
/// Wrappers that do not change what an expression names.
const TRANSPARENT: &[&str] = &[
    "parenthesized_expression",
    "await_expression",
    "non_null_expression",
    "as_expression",
    "satisfies_expression",
    "type_assertion",
];

/// Rules for JavaScript, or TypeScript when `typescript` is set.
pub struct JsRules {
    pub typescript: bool,
}

impl LangRules for JsRules {
    fn language(&self) -> Language {
        if self.typescript {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
        } else {
            tree_sitter_javascript::LANGUAGE.into()
        }
    }

    fn facts(&self, tree: &Tree, src: &str) -> Facts {
        let mut x = Extract::new(src.as_bytes());
        let complete = x.collect(tree, self.query());
        let mut facts = x.finish();
        facts.budget_exceeded |= !complete;
        facts
    }
}

impl JsRules {
    fn query(&self) -> &'static Query {
        static JS: OnceLock<Query> = OnceLock::new();
        static TS: OnceLock<Query> = OnceLock::new();
        let (cell, extra) = if self.typescript {
            (&TS, QUERY_TS)
        } else {
            (&JS, QUERY_JS)
        };
        cell.get_or_init(|| {
            Query::new(&self.language(), &format!("{QUERY_COMMON}{extra}"))
                .expect("javascript query is valid")
        })
    }
}

/// Text inside the quotes of a string or template literal.
fn string_content(text: &str) -> &str {
    let t = text.strip_prefix(['"', '\'', '`']).unwrap_or(text);
    t.strip_suffix(['"', '\'', '`']).unwrap_or(t)
}

/// Module name of a `require`/`import` specifier: `node:fs/promises` is
/// `fs.promises`.
fn module_name(spec: &str) -> String {
    spec.strip_prefix("node:").unwrap_or(spec).replace('/', ".")
}

/// Drops leading `globalThis.`, `window.`, `global.` and `self.`.
fn strip_global(mut name: &str) -> &str {
    for _ in 0..MAX_NAME_SEGMENTS {
        match ["globalThis.", "window.", "global.", "self."]
            .iter()
            .find_map(|p| name.strip_prefix(p))
        {
            Some(rest) => name = rest,
            None => break,
        }
    }
    name
}

/// `setTimeout`/`setInterval`, which evaluate a string first argument.
fn is_timer(name: &str) -> bool {
    matches!(strip_global(name), "setTimeout" | "setInterval")
}

/// Whether a resolved name loads modules like `require`.
fn is_require(name: &str) -> bool {
    matches!(strip_global(name), "require" | "module.require")
}

/// Names the rules classify: a call resolving to one of these is preferred
/// over its other possible meanings.
fn relevant(name: &str) -> bool {
    sink_class(name).is_some()
        || is_env_call(name)
        || is_connect(name)
        || is_path_builder(name)
        || is_timer(name)
        || name == "os.homedir"
        || name.starts_with("fs.")
        || last_segment(name) == "pipe"
}

fn dots(name: &str) -> usize {
    name.matches('.').count()
}

/// `(constructor, method)` of a call on a client object, such as
/// `("https.request", "end")` for `https.request().end`.
fn client_call(name: &str) -> Option<(&str, &str)> {
    let (ctor, method) = name.split_once("().")?;
    (!method.contains(['.', '('])).then_some((ctor, method))
}

/// Sink class of a resolved call or constructor name.
fn sink_class(name: &str) -> Option<&'static str> {
    let name = strip_global(name);
    if let Some((ctor, method)) = client_call(name) {
        return client_sink(ctor, method);
    }
    let root = name.split(['.', '(']).next().unwrap_or("");
    let last = last_segment(name);
    let one_dot = dots(name) == 1 && !name.contains('(');
    let class = match root {
        "fetch" | "node-fetch" | "axios" | "got" if name == root => NETWORK,
        "axios" | "got" if one_dot && HTTP_VERBS.contains(&last) => NETWORK,
        "undici" if one_dot && matches!(last, "fetch" | "request" | "stream") => NETWORK,
        "http" | "https" if one_dot && matches!(last, "request" | "get") => NETWORK,
        "net" if one_dot && matches!(last, "connect" | "createConnection") => NETWORK,
        "tls" if name == "tls.connect" => NETWORK,
        "WebSocket" | "ws" if name == root || name == "ws.WebSocket" => NETWORK,
        "navigator" if name == "navigator.sendBeacon" => NETWORK,
        "child_process" if one_dot && EXEC_FUNCS.contains(&last) => EXEC,
        "zx" if name == "zx.$" => EXEC,
        "eval" | "Function" if name == root => EVAL,
        "vm" if one_dot
            && (last.starts_with("runIn") || matches!(last, "compileFunction" | "Script")) =>
        {
            EVAL
        }
        _ => return None,
    };
    Some(class)
}

fn client_sink(ctor: &str, method: &str) -> Option<&'static str> {
    let class = match ctor {
        "http.request" | "http.get" | "https.request" | "https.get"
            if matches!(method, "write" | "end") =>
        {
            NETWORK
        }
        "net.Socket" | "net.connect" | "net.createConnection" | "tls.connect" | "tls.TLSSocket"
            if matches!(method, "write" | "end" | "connect") =>
        {
            NETWORK
        }
        "WebSocket" | "ws" | "ws.WebSocket" if method == "send" => NETWORK,
        "XMLHttpRequest" if method == "send" => NETWORK,
        "axios.create" | "got.extend" if HTTP_VERBS.contains(&method) => NETWORK,
        _ => return None,
    };
    Some(class)
}

fn is_path_builder(name: &str) -> bool {
    PATH_BUILDERS.contains(&name)
}

fn is_connect(name: &str) -> bool {
    matches!(
        name,
        "net.connect" | "net.createConnection" | "tls.connect" | "net.Socket().connect"
    )
}

fn is_env_call(name: &str) -> bool {
    name == "Deno.env.get"
}

/// The secret-looking variable name of a `process.env.NAME` read.
fn env_member(name: &str) -> Option<&str> {
    let key = ["process.env.", "Bun.env."]
        .iter()
        .find_map(|p| strip_global(name).strip_prefix(p))?;
    (!key.is_empty() && !key.contains(['.', '('])).then_some(key)
}

enum FoldItem<'t> {
    Node(Node<'t>),
    Sep,
}

struct Extract<'t> {
    core: Core<'t>,
    /// Plain string literals (and templates without substitutions).
    strings: Vec<Node<'t>>,
    /// Candidates for folding: `+` expressions and templates with
    /// substitutions.
    folds: Vec<Node<'t>>,
    /// Member and subscript expressions, for `process.env.NAME`.
    members: Vec<Node<'t>>,
    /// `const { NAME: local } = process.env`: pattern node, NAME, local.
    env_patterns: Vec<(Node<'t>, String, String)>,
    /// Enclosing functions: the name a `return` binds, and the end byte.
    funcs: Vec<(Option<String>, usize)>,
    /// Names declared as functions anywhere in the file.
    fn_names: HashSet<String>,
    /// Callback bindings whose first-argument range is a plain name: bind
    /// index, the name and its range. Dropped at the end when the name is a
    /// function.
    callback_firsts: Vec<(usize, String, (usize, usize))>,
}

impl<'t> Extract<'t> {
    fn new(src: &'t [u8]) -> Self {
        Self {
            core: Core::new(src),
            strings: Vec::new(),
            folds: Vec::new(),
            members: Vec::new(),
            env_patterns: Vec::new(),
            funcs: Vec::new(),
            fn_names: HashSet::new(),
            callback_firsts: Vec::new(),
        }
    }

    fn text(&self, node: Node) -> &'t str {
        self.core.text(node)
    }

    /// Property name, with a private `#name` rewritten to `%name`.
    fn prop_name(&self, node: Node) -> Option<String> {
        let t = self.text(node);
        match node.kind() {
            "private_property_identifier" => Some(format!("%{}", t.trim_start_matches('#'))),
            "property_identifier" | "identifier" => Some(t.to_string()),
            _ => None,
        }
    }

    /// Unwraps parentheses, `await` and type assertions.
    fn unwrap<'n>(&self, mut node: Node<'n>) -> Node<'n> {
        for _ in 0..MAX_NAME_SEGMENTS {
            if !TRANSPARENT.contains(&node.kind()) {
                break;
            }
            let inner = if node.kind() == "type_assertion" {
                self.core.children(node).last().copied()
            } else {
                self.core.first_child(node)
            };
            match inner {
                Some(n) => node = n,
                None => break,
            }
        }
        node
    }

    /// Resolved name of a plain or one-level dotted name (`require`,
    /// `module.require`), without walking into calls.
    fn simple_name(&self, node: Node) -> Option<Vec<String>> {
        let node = self.unwrap(node);
        let simple = match node.kind() {
            "identifier" => true,
            "member_expression" => node
                .child_by_field_name("object")
                .is_some_and(|o| o.kind() == "identifier"),
            _ => false,
        };
        if !simple {
            return None;
        }
        self.dotted(node, false).map(|n| self.core.resolutions(&n))
    }

    /// Whether `call` is `createRequire(...)`, which returns a `require`.
    fn is_create_require(&self, call: Node) -> bool {
        call.kind() == "call_expression"
            && call
                .child_by_field_name("function")
                .and_then(|f| self.simple_name(f))
                .is_some_and(|all| all.iter().any(|n| last_segment(n) == "createRequire"))
    }

    /// Module of a module-loading call: `require("m")`, `import("m")`, an
    /// alias of `require`, `module.require("m")` or
    /// `createRequire(url)("m")`.
    fn required(&self, call: Node) -> Option<String> {
        if call.kind() != "call_expression" {
            return None;
        }
        let f = self.unwrap(call.child_by_field_name("function")?);
        let loads = match f.kind() {
            "import" => true,
            "call_expression" => self.is_create_require(f),
            _ => self
                .simple_name(f)
                .is_some_and(|all| all.iter().any(|n| is_require(n))),
        };
        if !loads {
            return None;
        }
        let arg = self
            .core
            .first_child(call.child_by_field_name("arguments")?)?;
        (arg.kind() == "string").then(|| module_name(string_content(self.text(arg))))
    }

    /// Dotted name such as `net.Socket().write`; calls are allowed only when
    /// `calls` is set. `require("m")` stands for module `m`, a string index
    /// for a property, and parentheses, `await` and type assertions are
    /// looked through. `None` for other shapes or overly long chains.
    fn dotted(&self, node: Node, calls: bool) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        let mut suffix = String::new();
        let mut cur = node;
        for _ in 0..MAX_NAME_SEGMENTS {
            let head = match cur.kind() {
                "identifier" | "this" => Some(self.text(cur).to_string()),
                "call_expression" => self.required(cur),
                _ => None,
            };
            if let Some(head) = head {
                parts.push(format!("{head}{suffix}"));
                parts.reverse();
                return Some(parts.join("."));
            }
            match cur.kind() {
                "member_expression" => {
                    let p = self.prop_name(cur.child_by_field_name("property")?)?;
                    parts.push(format!("{p}{suffix}"));
                    suffix.clear();
                    cur = cur.child_by_field_name("object")?;
                }
                "subscript_expression" => {
                    let idx = cur.child_by_field_name("index")?;
                    if idx.kind() != "string" {
                        return None;
                    }
                    parts.push(format!("{}{suffix}", string_content(self.text(idx))));
                    suffix.clear();
                    cur = cur.child_by_field_name("object")?;
                }
                "call_expression" if calls => {
                    suffix.push_str("()");
                    cur = cur.child_by_field_name("function")?;
                }
                "new_expression" if calls => {
                    suffix.push_str("()");
                    cur = cur.child_by_field_name("constructor")?;
                }
                "sequence_expression" => {
                    cur = self.core.children(cur).last().copied()?;
                }
                k if TRANSPARENT.contains(&k) => {
                    let inner = self.unwrap(cur);
                    if inner == cur {
                        return None;
                    }
                    cur = inner;
                }
                _ => return None,
            }
        }
        None
    }

    /// Unresolved name of what a call or `new` expression invokes.
    fn callee_of(&self, node: Node) -> Option<String> {
        let f = match node.kind() {
            "call_expression" => node.child_by_field_name("function")?,
            "new_expression" => node.child_by_field_name("constructor")?,
            _ => return None,
        };
        self.dotted(f, true)
    }

    /// Resolved name of a call, for folding paths.
    fn callee(&self, node: Node) -> Option<String> {
        let name = self.callee_of(node)?;
        Some(
            self.core
                .resolve_best(&name, |n| is_path_builder(n) || n == "os.homedir"),
        )
    }

    /// Everything a value may name when it stands for a module or a known
    /// global: `require("m")`, `import("m")`, `require("m").x`,
    /// `createRequire(url)`, an alias, or a dotted name under a known root.
    fn module_paths(&self, value: Node) -> Vec<String> {
        let value = self.unwrap(value);
        if let Some(m) = self.required(value) {
            return vec![m];
        }
        if self.is_create_require(value) {
            return vec!["require".to_string()];
        }
        if !matches!(
            value.kind(),
            "identifier" | "member_expression" | "subscript_expression"
        ) {
            return Vec::new();
        }
        let Some(name) = self.dotted(value, false) else {
            return Vec::new();
        };
        let all = self.core.resolutions(&name);
        let aliased = all.len() != 1 || all[0] != name;
        all.into_iter()
            .filter(|full| {
                let root = full.split(['.', '(']).next().unwrap_or("");
                aliased || KNOWN_ROOTS.contains(&root)
            })
            .collect()
    }

    /// Variable names bound by a target or parameter list.
    fn targets(&self, node: Node) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![node];
        let mut visited = 0;
        while let Some(n) = stack.pop() {
            visited += 1;
            if visited > MAX_FOLD_NODES {
                break;
            }
            match n.kind() {
                "identifier" | "shorthand_property_identifier_pattern" => {
                    out.push(self.text(n).to_string());
                }
                "member_expression" | "subscript_expression" => match self.dotted(n, false) {
                    Some(d) => out.push(d),
                    None => stack.extend(n.child_by_field_name("object")),
                },
                "pair_pattern" => stack.extend(n.child_by_field_name("value")),
                "assignment_pattern" | "object_assignment_pattern" => {
                    stack.extend(n.child_by_field_name("left"));
                }
                "required_parameter" | "optional_parameter" => {
                    stack.extend(n.child_by_field_name("pattern"));
                }
                "object_pattern"
                | "array_pattern"
                | "rest_pattern"
                | "formal_parameters"
                | "parenthesized_expression"
                | "non_null_expression" => stack.extend(self.core.children(n)),
                _ => {}
            }
        }
        out
    }

    fn bind(&mut self, targets: Vec<String>, rhs: Option<Node>, end: Option<usize>, line: u32) {
        let rhs_callee = rhs.and_then(|r| self.callee_of(self.unwrap(r)));
        self.core.bind(targets, rhs, end, line, rhs_callee);
    }

    fn alias(&mut self, local: &str, full: &str) {
        self.core.add_alias(local, strip_global(full).to_string());
    }

    /// First pass. Returns false when the time budget ran out.
    fn collect(&mut self, tree: &'t Tree, query: &Query) -> bool {
        let src = self.core.src;
        run_query(query, tree, src, |kind, node| self.capture(kind, node))
    }

    fn capture(&mut self, kind: &str, node: Node<'t>) {
        let ln = line(node);
        match kind {
            "ident" => self.core.token(node, self.text(node).to_string(), true),
            "member" => {
                self.members.push(node);
                if let Some(d) = self.dotted(node, false) {
                    self.core.token(node, d, false);
                }
            }
            "str" => {
                let substituted = node.kind() == "template_string"
                    && self.core.has_child_kind(node, "template_substitution");
                if substituted {
                    self.folds.push(node);
                } else {
                    self.strings.push(node);
                }
            }
            "binop" => {
                let op = node.child_by_field_name("operator").map(|o| o.kind());
                if op == Some("+") {
                    self.folds.push(node);
                }
            }
            "call" => self.call(node, ln),
            "decl" => self.declarator(node, ln),
            "assign" | "augassign" => {
                let Some(left) = node.child_by_field_name("left") else {
                    return;
                };
                let right = node.child_by_field_name("right");
                if kind == "assign" && self.bind_pairs(left, right, ln) {
                    return;
                }
                let targets = self.targets(left);
                let before = self.core.binds.len();
                self.bind(targets.clone(), right, None, ln);
                if kind == "augassign"
                    && self.core.binds.len() > before
                    && let Some(b) = self.core.binds.last_mut()
                {
                    b.extra = targets;
                }
            }
            "for" => {
                let targets = node
                    .child_by_field_name("left")
                    .map(|n| self.targets(n))
                    .unwrap_or_default();
                self.bind(targets, node.child_by_field_name("right"), None, ln);
            }
            "func" => self.function(node),
            "return" => {
                while self.funcs.last().is_some_and(|f| f.1 <= node.start_byte()) {
                    self.funcs.pop();
                }
                if let Some((Some(name), _)) = self.funcs.last() {
                    let name = name.clone();
                    self.bind(vec![name], Some(node), None, ln);
                }
            }
            "field" => {
                let prop = node
                    .child_by_field_name("property")
                    .or_else(|| node.child_by_field_name("name"));
                if let Some(p) = prop.and_then(|p| self.prop_name(p)) {
                    let value = node.child_by_field_name("value");
                    self.bind(vec![format!("this.{p}")], value, None, ln);
                }
            }
            "import" => self.import(node),
            _ => {}
        }
    }

    /// A function: named ones bind what they return; methods bind it to
    /// `this.<name>`; anonymous ones bind nothing.
    fn function(&mut self, node: Node) {
        let name = node.child_by_field_name("name");
        let bound = match (node.kind(), name) {
            ("method_definition", Some(n)) => self.prop_name(n).map(|p| format!("this.{p}")),
            (_, Some(n)) if n.kind() == "identifier" => {
                self.core.not_values.insert(n.start_byte());
                self.fn_names.insert(self.text(n).to_string());
                Some(self.text(n).to_string())
            }
            _ => None,
        };
        self.funcs.push((bound, node.end_byte()));
    }

    /// First parameter node of a function, looking through TypeScript
    /// parameter wrappers and defaults.
    fn first_param(&self, f: Node<'t>) -> Option<Node<'t>> {
        let mut p = match f.child_by_field_name("parameter") {
            Some(p) => p,
            None => self
                .core
                .first_child(f.child_by_field_name("parameters")?)?,
        };
        for _ in 0..4 {
            p = match p.kind() {
                "required_parameter" | "optional_parameter" => p.child_by_field_name("pattern")?,
                "assignment_pattern" => p.child_by_field_name("left")?,
                _ => return Some(p),
            };
        }
        Some(p)
    }

    /// Records a call. Parameters of a callback passed to it receive the
    /// call's result, its receiver and its first argument when that is a
    /// value (the path of `fs.readFile(path, cb)`). They never take taint
    /// from other arguments (the data of `fs.writeFile(path, data, cb)`),
    /// from sibling callbacks, or from a first argument that names a
    /// function. `import("m").then(cb)` makes `cb`'s first parameter an
    /// alias of module `m`.
    fn call(&mut self, node: Node<'t>, ln: u32) {
        let callee = self.callee_of(node);
        let args = node.child_by_field_name("arguments");
        self.core.add_call(node, callee, args);
        let Some(args) = args.filter(|a| a.kind() == "arguments") else {
            return;
        };
        let args = self.core.children(args);
        let is_fn = |a: &Node| matches!(a.kind(), "arrow_function" | "function_expression");
        let callbacks: Vec<Node<'t>> = args.iter().copied().filter(is_fn).collect();
        let Some(first_cb) = callbacks.first().copied() else {
            return;
        };
        let member = node
            .child_by_field_name("function")
            .filter(|f| f.kind() == "member_expression");
        let receiver = member.and_then(|f| f.child_by_field_name("object"));
        let then = member
            .and_then(|f| f.child_by_field_name("property"))
            .is_some_and(|p| self.text(p) == "then");
        if then
            && let Some(m) = receiver.and_then(|r| self.required(self.unwrap(r)))
            && let Some(p) = self.first_param(first_cb)
        {
            self.alias_pattern(p, &m);
        }

        let mut params = Vec::new();
        for cb in &callbacks {
            let p = cb
                .child_by_field_name("parameters")
                .or_else(|| cb.child_by_field_name("parameter"));
            params.extend(p.map(|p| self.targets(p)).unwrap_or_default());
        }
        let mut ranges: Vec<(usize, usize)> = receiver
            .map(|r| (r.start_byte(), r.end_byte()))
            .into_iter()
            .collect();
        let first = args.first().copied().filter(|a| !is_fn(a));
        if let Some(a) = first {
            ranges.push((a.start_byte(), a.end_byte()));
        }
        let id = self.core.calls.last().map(|c| c.id.clone());
        let before = self.core.binds.len();
        self.core.push_bind(Bind {
            targets: params,
            ranges,
            extra: id.into_iter().collect(),
            line: ln,
            rhs_callee: None,
        });
        if let Some(a) = first.filter(|a| a.kind() == "identifier")
            && self.core.binds.len() > before
        {
            let range = (a.start_byte(), a.end_byte());
            self.callback_firsts
                .push((before, self.text(a).to_string(), range));
        }
    }

    fn declarator(&mut self, node: Node<'t>, ln: u32) {
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let Some(value) = node.child_by_field_name("value") else {
            return;
        };
        if name.kind() == "identifier"
            && matches!(
                self.unwrap(value).kind(),
                "arrow_function" | "function_expression"
            )
        {
            self.fn_names.insert(self.text(name).to_string());
        }
        for full in self.module_paths(value) {
            self.alias_pattern(name, &full);
        }
        if self.bind_pairs(name, Some(value), ln) {
            return;
        }
        let targets = self.targets(name);
        self.bind(targets, Some(value), None, ln);
    }

    /// Aliases from `const x = <module>` and `const { a, b: c } = <module>`;
    /// destructuring `process.env` records environment reads instead.
    fn alias_pattern(&mut self, pattern: Node<'t>, full: &str) {
        match pattern.kind() {
            "identifier" => self.alias(self.text(pattern), full),
            "object_pattern" => {
                for p in self.core.children(pattern).into_iter() {
                    let pair = match p.kind() {
                        "shorthand_property_identifier_pattern" => Some((p, p)),
                        "object_assignment_pattern" => {
                            p.child_by_field_name("left").map(|l| (l, l))
                        }
                        "pair_pattern" => {
                            let value = p.child_by_field_name("value").map(|v| {
                                if v.kind() == "assignment_pattern" {
                                    v.child_by_field_name("left").unwrap_or(v)
                                } else {
                                    v
                                }
                            });
                            p.child_by_field_name("key").zip(value)
                        }
                        _ => None,
                    };
                    let Some((key, local)) = pair else { continue };
                    let key = match key.kind() {
                        "string" => string_content(self.text(key)),
                        "property_identifier" | "shorthand_property_identifier_pattern" => {
                            self.text(key)
                        }
                        _ => continue,
                    };
                    if !matches!(
                        local.kind(),
                        "identifier" | "shorthand_property_identifier_pattern"
                    ) {
                        continue;
                    }
                    let local = self.text(local);
                    if full == "process.env" {
                        self.env_patterns
                            .push((p, key.to_string(), local.to_string()));
                    } else {
                        self.alias(local, &format!("{full}.{key}"));
                    }
                }
            }
            _ => {}
        }
    }

    /// Elements of an array literal or pattern, or `None` when it has holes,
    /// comments or spreads (positions would not line up).
    fn elements(node: Node<'t>) -> Option<Vec<Node<'t>>> {
        let count = node.child_count();
        if count > 2 * 64 + 2 {
            return None;
        }
        let mut out = Vec::new();
        let mut after_comma = true;
        for i in 0..count {
            let c = node.child(i)?;
            match c.kind() {
                "[" | "]" => {}
                "," if after_comma => return None,
                "," => after_comma = true,
                "comment" | "rest_pattern" | "spread_element" => return None,
                _ if c.is_named() && after_comma => {
                    out.push(c);
                    after_comma = false;
                }
                _ => return None,
            }
        }
        Some(out)
    }

    /// `[a, b] = [x, y]`: binds each target to its own element. False when
    /// the sides are not array literals of the same simple shape.
    fn bind_pairs(&mut self, left: Node<'t>, right: Option<Node<'t>>, line: u32) -> bool {
        let Some(right) = right else { return false };
        if left.kind() != "array_pattern" || right.kind() != "array" {
            return false;
        }
        let (Some(l), Some(r)) = (Self::elements(left), Self::elements(right)) else {
            return false;
        };
        if l.len() != r.len() {
            return false;
        }
        for (l, r) in l.into_iter().zip(r) {
            let targets = self.targets(l);
            self.bind(targets, Some(r), None, line);
        }
        true
    }

    /// Module named by a node's `source` string.
    fn source_module(&self, node: Node) -> Option<String> {
        node.child_by_field_name("source")
            .filter(|s| s.kind() == "string")
            .map(|s| module_name(string_content(self.text(s))))
    }

    fn import(&mut self, node: Node<'t>) {
        let source = self.source_module(node);
        for c in self.core.children(node).into_iter() {
            match (c.kind(), &source) {
                ("import_clause", Some(m)) => self.import_clause(c, m),
                ("import_require_clause", _) => {
                    let local = self
                        .core
                        .children(c)
                        .into_iter()
                        .find(|n| n.kind() == "identifier");
                    if let (Some(m), Some(l)) = (self.source_module(c), local) {
                        self.alias(self.text(l), &m);
                    }
                }
                _ => {}
            }
        }
    }

    fn import_clause(&mut self, clause: Node<'t>, module: &str) {
        for c in self.core.children(clause).into_iter() {
            match c.kind() {
                "identifier" => self.alias(self.text(c), module),
                "namespace_import" => {
                    if let Some(id) = self
                        .core
                        .children(c)
                        .into_iter()
                        .find(|n| n.kind() == "identifier")
                    {
                        self.alias(self.text(id), module);
                    }
                }
                "named_imports" => {
                    for s in self
                        .core
                        .children(c)
                        .into_iter()
                        .filter(|s| s.kind() == "import_specifier")
                    {
                        let Some(name) = s.child_by_field_name("name") else {
                            continue;
                        };
                        let name = string_content(self.text(name));
                        let local = s
                            .child_by_field_name("alias")
                            .map_or(name, |a| self.text(a));
                        let full = if name == "default" {
                            module.to_string()
                        } else {
                            format!("{module}.{name}")
                        };
                        self.alias(local, &full);
                    }
                }
                _ => {}
            }
        }
    }
}

impl<'t> Extract<'t> {
    /// Path text an expression builds from string and template literals,
    /// `+`, `path.join`/`path.resolve` and `os.homedir()` (or
    /// `process.env.HOME`) as `~`. Ids of the nodes it walked go into
    /// `visited`.
    fn fold(&self, node: Node<'t>, visited: &mut HashSet<usize>) -> String {
        let mut out = String::new();
        let mut stack = vec![FoldItem::Node(node)];
        let mut steps = 0;
        let push_children = |stack: &mut Vec<FoldItem<'t>>, n: Node<'t>, sep: bool| {
            let kids: Vec<Node<'t>> = self.core.children(n).into_iter().collect();
            for (i, c) in kids.into_iter().enumerate().rev() {
                stack.push(FoldItem::Node(c));
                if sep && i > 0 {
                    stack.push(FoldItem::Sep);
                }
            }
        };
        while let Some(item) = stack.pop() {
            let n = match item {
                FoldItem::Sep => {
                    out.push('/');
                    continue;
                }
                FoldItem::Node(n) => n,
            };
            steps += 1;
            if steps > MAX_FOLD_NODES {
                break;
            }
            visited.insert(n.id());
            match n.kind() {
                "string" => out.push_str(string_content(self.text(n))),
                "string_fragment" | "escape_sequence" => out.push_str(self.text(n)),
                "template_string" | "template_substitution" | "parenthesized_expression" => {
                    push_children(&mut stack, n, false);
                }
                "binary_expression" => {
                    let parts = (
                        n.child_by_field_name("left"),
                        n.child_by_field_name("operator").map(|o| o.kind()),
                        n.child_by_field_name("right"),
                    );
                    if let (Some(l), Some("+"), Some(r)) = parts {
                        stack.push(FoldItem::Node(r));
                        stack.push(FoldItem::Node(l));
                    }
                }
                "call_expression" => {
                    let name = self.callee(n).unwrap_or_default();
                    if is_path_builder(&name) {
                        if let Some(args) = n.child_by_field_name("arguments") {
                            push_children(&mut stack, args, true);
                        }
                    } else if name == "os.homedir" {
                        out.push('~');
                    }
                }
                "member_expression" => {
                    let home = self.dotted(n, false).and_then(|d| {
                        self.core.resolve_where(&d, |r| {
                            matches!(env_member(r), Some("HOME" | "USERPROFILE"))
                        })
                    });
                    if home.is_some() {
                        out.push('~');
                    }
                }
                _ => {}
            }
        }
        normalize_path(&out)
    }

    /// String literal sources and sensitive paths, with their spans.
    fn literal_sites(&mut self) -> Vec<(usize, usize, &'static str)> {
        let mut spans = Vec::new();
        for s in std::mem::take(&mut self.strings) {
            let content = string_content(self.text(s));
            if let Some(class) = literal_source_class(content) {
                let text = self.core.describe_in_call(s, content, is_path_builder);
                self.core.add_source(s, class, text, None);
                spans.push((s.start_byte(), s.end_byte(), class));
            }
            if is_sensitive_write_path(content) {
                self.core.add_sensitive(s);
                spans.push((s.start_byte(), s.end_byte(), SENSITIVE_WRITE));
            }
        }
        spans
    }

    /// Sources and sensitive paths assembled from several pieces, as in the
    /// Python rules: an enclosing fold covers what it walked, and a match is
    /// reported only when no single literal inside already matched.
    fn fold_sites(&mut self, spans: &[(usize, usize, &str)]) {
        let mut cands = std::mem::take(&mut self.folds);
        cands.extend(
            self.core
                .calls
                .iter()
                .filter(|c| c.callee.as_deref().is_some_and(is_path_builder))
                .map(|c| c.node),
        );
        cands.sort_by_key(|n| (n.start_byte(), std::cmp::Reverse(n.end_byte())));
        let mut visited = HashSet::new();
        for n in cands {
            if visited.contains(&n.id()) {
                continue;
            }
            let folded = self.fold(n, &mut visited);
            if folded.is_empty() {
                continue;
            }
            if let Some(class) = literal_source_class(&folded)
                && !Core::has_span_within(spans, n, class)
            {
                let text = self.core.describe_in_call(n, &folded, is_path_builder);
                self.core.add_source(n, class, text, None);
            }
            if is_sensitive_write_path(&folded) && !Core::has_span_within(spans, n, SENSITIVE_WRITE)
            {
                self.core.add_sensitive(n);
            }
        }
    }

    /// `process.env.NAME` and `process.env["NAME"]` reads of secret-looking
    /// variables.
    fn env_members(&mut self) {
        for m in std::mem::take(&mut self.members) {
            let found = self.dotted(m, false).and_then(|d| {
                self.core.resolve_where(&d, |r| {
                    env_member(r).is_some_and(|k| env_class(k).is_some())
                })
            });
            let Some(name) = found else {
                continue;
            };
            let Some(key) = env_member(&name) else {
                continue;
            };
            if let Some(class) = env_class(key) {
                let text = clip(strip_global(&name), TEXT_CHARS);
                self.core.add_source(m, class, text, None);
            }
        }
    }

    /// `const { NAME } = process.env`: a source bound to the local name.
    fn env_patterns(&mut self) {
        for (node, key, local) in std::mem::take(&mut self.env_patterns) {
            let Some(class) = env_class(&key) else {
                continue;
            };
            let before = self.core.sources.len();
            let text = format!("process.env.{}", clip(&key, TEXT_CHARS));
            self.core.add_source(node, class, text, None);
            let Some(id) = self.core.sources.get(before).map(|s| s.id.clone()) else {
                continue;
            };
            self.core.push_bind(Bind {
                targets: vec![local],
                ranges: Vec::new(),
                extra: vec![id],
                line: line(node),
                rhs_callee: None,
            });
        }
    }

    /// `Deno.env.get("NAME")` reads.
    fn env_calls(&mut self) {
        let calls = std::mem::take(&mut self.core.calls);
        for c in &calls {
            let Some(name) = c.callee.as_deref() else {
                continue;
            };
            if !is_env_call(name) {
                continue;
            }
            let key = c
                .args
                .and_then(|a| self.core.first_child(a))
                .filter(|k| k.kind() == "string")
                .map(|k| string_content(self.text(k)));
            if let Some((key, class)) = key.and_then(|k| Some((k, env_class(k)?))) {
                let text = format!("{name}({})", clip(key, TEXT_CHARS));
                self.core
                    .add_source(c.node, class, text, Some(c.id.clone()));
            }
        }
        self.core.calls = calls;
    }

    /// Positional arguments of a call (up to 8), comments skipped.
    fn positional(&self, args: Node<'t>) -> Vec<Node<'t>> {
        self.core.children(args).into_iter().take(8).collect()
    }

    fn is_str(n: &Node) -> bool {
        matches!(n.kind(), "string" | "template_string")
    }

    /// Text of a command built from string and template literals and `+`.
    /// Other pieces stand in as an unknown character. `None` when no literal
    /// is involved.
    fn command_text(&self, node: Node<'t>) -> Option<String> {
        let mut out = String::new();
        let mut literal = false;
        let mut stack = vec![node];
        let mut steps = 0;
        while let Some(n) = stack.pop() {
            steps += 1;
            if steps > MAX_FOLD_NODES {
                self.core.truncate();
                break;
            }
            match n.kind() {
                "string" => {
                    literal = true;
                    out.push_str(string_content(self.text(n)));
                }
                "string_fragment" | "escape_sequence" => out.push_str(self.text(n)),
                "template_string" => {
                    literal = true;
                    stack.extend(self.core.children(n).into_iter().rev());
                }
                "template_substitution" | "parenthesized_expression" => {
                    stack.extend(self.core.children(n).into_iter().rev());
                }
                "binary_expression"
                    if n.child_by_field_name("operator").map(|o| o.kind()) == Some("+") =>
                {
                    stack.extend(n.child_by_field_name("right"));
                    stack.extend(n.child_by_field_name("left"));
                }
                _ => out.push(UNKNOWN_PIECE),
            }
        }
        literal.then_some(out)
    }

    /// The program and argument words of `spawn(prog, [args])`-style calls,
    /// with an `env` launcher dropped, when the program is a literal.
    fn argv(&self, c: &Call<'t>) -> Vec<String> {
        let Some(args) = c.args.filter(|a| a.kind() == "arguments") else {
            return Vec::new();
        };
        let pos = self.positional(args);
        let Some(prog) = pos.first().and_then(|f| self.command_text(*f)) else {
            return Vec::new();
        };
        let mut words = vec![prog];
        if let Some(arr) = pos.get(1).filter(|a| a.kind() == "array") {
            words.extend(
                self.core
                    .children(*arr)
                    .into_iter()
                    .filter_map(|n| self.command_text(n)),
            );
        }
        if ENV_LAUNCHERS.contains(&words[0].as_str()) {
            words.remove(0);
        }
        words
    }

    /// Whether the call starts a shell, as in `spawn("/bin/sh")` or
    /// `spawn("/usr/bin/env", ["bash", ...])`.
    fn spawns_shell(&self, c: &Call<'t>) -> bool {
        self.argv(c)
            .first()
            .is_some_and(|p| SHELLS.contains(&p.as_str()))
    }

    /// Whether an options object passes `shell` (other than `false`).
    fn shell_option(&self, args: &[Node<'t>]) -> bool {
        args.iter().filter(|a| a.kind() == "object").any(|o| {
            self.core.children(*o).into_iter().any(|p| {
                p.kind() == "pair"
                    && p.child_by_field_name("key")
                        .is_some_and(|k| string_content(self.text(k)) == "shell")
                    && p.child_by_field_name("value")
                        .is_some_and(|v| self.text(v) != "false")
            })
        })
    }

    /// Whether an exec call runs a shell command that fetches with curl or
    /// wget and pipes the result into a shell.
    fn runs_fetch_pipe(&self, c: &Call<'t>, name: &str) -> bool {
        let Some(args) = c.args else {
            return false;
        };
        if args.kind() == "template_string" {
            return self
                .command_text(args)
                .is_some_and(|t| pipes_download_to_shell(&t));
        }
        let pos = self.positional(args);
        let Some(first) = pos.first().copied() else {
            return false;
        };
        let shell_cmd = matches!(last_segment(name), "exec" | "execSync");
        let commands: Vec<String> = if shell_cmd || self.shell_option(&pos) {
            self.command_text(first).into_iter().collect()
        } else {
            let words = self.argv(c);
            let shell = words.first().is_some_and(|p| SHELLS.contains(&p.as_str()));
            if shell && words.iter().any(|w| SHELL_FLAGS.contains(&w.as_str())) {
                words
            } else {
                Vec::new()
            }
        };
        commands.iter().any(|t| pipes_download_to_shell(t))
    }

    /// Whether `setTimeout`/`setInterval` gets code as a string.
    fn timer_evaluates(&self, c: &Call<'t>) -> bool {
        let first = c
            .args
            .filter(|a| a.kind() == "arguments")
            .and_then(|a| self.core.first_child(a));
        first.is_some_and(|f| {
            let f = self.unwrap(f);
            Self::is_str(&f) || (f.kind() == "binary_expression" && self.command_text(f).is_some())
        })
    }

    /// Whether an `fs` call writes to a path that a sensitive literal reaches.
    fn writes_sensitive(&self, c: &Call<'t>, name: &str, sensitive: &HashSet<String>) -> bool {
        if !name.starts_with("fs.") {
            return false;
        }
        let Some(args) = c.args else {
            return false;
        };
        let pos = self.positional(args);
        let path = match last_segment(name) {
            "writeFile" | "writeFileSync" | "appendFile" | "appendFileSync"
            | "createWriteStream" | "truncate" | "truncateSync" => pos.first(),
            "open" | "openSync" => {
                let flags = pos
                    .get(1)
                    .filter(|f| Self::is_str(f))
                    .map(|f| string_content(self.text(*f)));
                if !flags.is_some_and(|f| f.contains(['w', 'a', '+'])) {
                    return false;
                }
                pos.first()
            }
            "copyFile" | "copyFileSync" | "cp" | "cpSync" | "rename" | "renameSync" | "symlink"
            | "symlinkSync" | "link" | "linkSync" => pos.get(1),
            _ => None,
        };
        path.is_some_and(|p| {
            self.core
                .node_refs(*p)
                .iter()
                .any(|r| sensitive.contains(r))
        })
    }

    /// Every sink.
    fn call_sites(&mut self, sensitive: &HashSet<String>) -> Vec<Site> {
        let mut sinks = Vec::new();
        let (mut connect, mut pipe) = (false, false);
        let mut shell_spawn: Option<usize> = None;
        let calls = std::mem::take(&mut self.core.calls);
        for (idx, c) in calls.iter().enumerate() {
            let Some(name) = c.callee.as_deref() else {
                continue;
            };
            if is_env_call(name) {
                continue;
            }
            connect |= is_connect(name);
            pipe |= last_segment(name) == "pipe";
            let class = match sink_class(name) {
                Some(EXEC) if self.runs_fetch_pipe(c, name) => Some(DOWNLOAD_EXEC),
                Some(class) => Some(class),
                None if is_timer(name) => self.timer_evaluates(c).then_some(EVAL),
                None => self
                    .writes_sensitive(c, name, sensitive)
                    .then_some(SENSITIVE_WRITE),
            };
            let Some(class) = class else { continue };
            if class == EXEC && shell_spawn.is_none() && self.spawns_shell(c) {
                shell_spawn = Some(idx);
            }
            let text = (c.node.kind() == "new_expression")
                .then(|| format!("new {}(...)", clip(name, TEXT_CHARS)));
            self.core
                .push_sink(&mut sinks, || self.core.sink(c, name, class, text));
        }
        if let (true, true, Some(i)) = (connect, pipe, shell_spawn) {
            let c = &calls[i];
            let name = c.callee.as_deref().unwrap_or_default();
            let text = format!("socket connect + {}(...)", clip(name, TEXT_CHARS));
            sinks.push(self.core.sink(c, name, REVERSE_SHELL, Some(text)));
        }
        self.core.calls = calls;
        sinks
    }

    /// Second pass: classify, resolve references and build the facts.
    fn finish(mut self) -> Facts {
        self.core.resolve_calls(CLIENT_CONSTRUCTORS, relevant);
        for (i, name, range) in std::mem::take(&mut self.callback_firsts) {
            if self.fn_names.contains(&name)
                && let Some(b) = self.core.binds.get_mut(i)
            {
                b.ranges.retain(|r| *r != range);
            }
        }
        let spans = self.literal_sites();
        self.fold_sites(&spans);
        self.env_members();
        self.env_patterns();
        self.env_calls();
        self.core.index_tokens();

        let network: Vec<String> = self
            .core
            .calls
            .iter()
            .filter(|c| {
                c.callee
                    .as_deref()
                    .is_some_and(|n| sink_class(n) == Some(NETWORK))
            })
            .map(|c| c.id.clone())
            .collect();
        self.core.set_interesting(network);

        let assigns = self.core.assigns();
        let sensitive = self.core.sensitive_reach(&assigns);
        let sinks = self.call_sites(&sensitive);
        self.core.into_facts(sinks, assigns)
    }
}
