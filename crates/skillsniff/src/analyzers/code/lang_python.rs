//! Python facts from a tree-sitter-python tree.
//!
//! One query pass collects identifiers, strings, calls and binding forms in
//! document order; a second step resolves import aliases, classifies sites and
//! turns byte ranges into the identifiers and site ids they reference.

use std::collections::HashSet;
use std::sync::OnceLock;

use tree_sitter::{Language, Node, Query, Tree};

use super::common::{
    Call, Core, MAX_FOLD_NODES, MAX_NAME_SEGMENTS, TEXT_CHARS, last_segment, line, run_query,
};
use super::patterns::{
    DOWNLOAD_EXEC, EVAL, EXEC, NETWORK, REVERSE_SHELL, SENSITIVE_WRITE, SHELLS, UNKNOWN_PIECE,
    env_class, is_posix_shell, is_sensitive_write_path, is_shell_flag, literal_source_class,
    normalize_path, pipes_download_to_shell,
};
use super::taint::{Facts, Site};
use super::{LangRules, clip};

const QUERY: &str = r#"
(identifier) @ident
(attribute) @attr
(string) @str
(expression_statement (string) @doc)
(binary_operator) @binop
(call) @call
(subscript) @subscript
(keyword_argument) @kwarg
(assignment) @assign
(augmented_assignment) @augassign
(named_expression) @walrus
(for_statement) @for
(for_in_clause) @for
(as_pattern) @as
(function_definition) @func
(return_statement) @return
(import_statement) @import
(import_from_statement) @import
"#;

const HTTP_VERBS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "send",
    "urlopen",
];
/// Constructors whose result is a network client: after `s = <ctor>(...)`,
/// `s.send(...)` resolves to `<ctor>().send(...)`. Responses are not clients.
const CLIENT_CONSTRUCTORS: &[&str] = &[
    "requests.Session",
    "requests.session",
    "httpx.Client",
    "httpx.AsyncClient",
    "urllib3.PoolManager",
    "urllib3.ProxyManager",
    "aiohttp.ClientSession",
    "socket.socket",
    "socket.create_connection",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "smtplib.SMTP",
    "smtplib.SMTP_SSL",
    "ftplib.FTP",
    "ftplib.FTP_TLS",
];
const PATH_BUILDERS: &[&str] = &[
    "pathlib.Path",
    "pathlib.PurePath",
    "pathlib.PosixPath",
    "pathlib.WindowsPath",
    "os.path.expanduser",
    "os.path.expandvars",
    "os.path.abspath",
    "os.path.realpath",
    "os.path.normpath",
];

/// Rules for Python scripts.
pub struct PythonRules;

impl LangRules for PythonRules {
    fn language(&self) -> Language {
        tree_sitter_python::LANGUAGE.into()
    }

    fn facts(&self, tree: &Tree, src: &str) -> Facts {
        let mut x = Extract::new(src.as_bytes());
        let complete = x.collect(tree);
        let mut facts = x.finish();
        facts.budget_exceeded |= !complete;
        facts
    }
}

fn query() -> &'static Query {
    static Q: OnceLock<Query> = OnceLock::new();
    Q.get_or_init(|| {
        Query::new(&tree_sitter_python::LANGUAGE.into(), QUERY).expect("python query is valid")
    })
}

/// Text inside the quotes of a Python string literal.
fn string_content(text: &str) -> &str {
    text.trim_start_matches(|c: char| c.is_ascii_alphabetic())
        .trim_matches(|c| c == '"' || c == '\'')
}

/// Sink class of a resolved call name.
fn sink_class(name: &str) -> Option<&'static str> {
    let root = name.split(['.', '(']).next().unwrap_or("");
    let last = last_segment(name);
    let dotted = name.contains('.');
    let class = match root {
        "requests" | "httpx" | "urllib3" | "aiohttp" if HTTP_VERBS.contains(&last) => NETWORK,
        "urllib" | "urllib2" if matches!(last, "urlopen" | "urlretrieve") => NETWORK,
        "http"
            if name.starts_with("http.client.")
                && matches!(last, "request" | "send" | "putrequest" | "endheaders") =>
        {
            NETWORK
        }
        "socket" if last.starts_with("send") => NETWORK,
        "smtplib" if matches!(last, "sendmail" | "send_message") => NETWORK,
        "ftplib" if matches!(last, "storbinary" | "storlines") => NETWORK,
        "subprocess"
            if matches!(
                last,
                "run"
                    | "call"
                    | "check_call"
                    | "check_output"
                    | "Popen"
                    | "getoutput"
                    | "getstatusoutput"
            ) =>
        {
            EXEC
        }
        "os" if name.matches('.').count() == 1
            && (matches!(last, "system" | "popen")
                || last.starts_with("exec")
                || last.starts_with("spawn")
                || last.starts_with("posix_spawn")) =>
        {
            EXEC
        }
        "eval" | "exec" | "compile" if !dotted => EVAL,
        "builtins" if matches!(name, "builtins.eval" | "builtins.exec" | "builtins.compile") => {
            EVAL
        }
        _ => return None,
    };
    Some(class)
}

fn is_path_builder(name: &str) -> bool {
    PATH_BUILDERS.contains(&name) || name.ends_with("path.join") || last_segment(name) == "joinpath"
}

fn is_connect(name: &str) -> bool {
    name == "socket.create_connection"
        || (name.starts_with("socket.") && matches!(last_segment(name), "connect" | "connect_ex"))
}

enum FoldItem<'t> {
    Node(Node<'t>),
    Sep,
}

struct Extract<'t> {
    core: Core<'t>,
    docstrings: HashSet<usize>,
    strings: Vec<Node<'t>>,
    binops: Vec<Node<'t>>,
    subscripts: Vec<Node<'t>>,
    funcs: Vec<(String, usize)>,
}

impl<'t> Extract<'t> {
    fn new(src: &'t [u8]) -> Self {
        Self {
            core: Core::new(src),
            docstrings: HashSet::new(),
            strings: Vec::new(),
            binops: Vec::new(),
            subscripts: Vec::new(),
            funcs: Vec::new(),
        }
    }

    fn text(&self, node: Node) -> &'t str {
        self.core.text(node)
    }

    /// Dotted name such as `requests.Session().post`; calls are allowed only
    /// when `calls` is set. `None` for other shapes or overly long chains.
    fn dotted(&self, node: Node, calls: bool) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        let mut suffix = String::new();
        let mut cur = node;
        for _ in 0..MAX_NAME_SEGMENTS {
            match cur.kind() {
                "identifier" => {
                    parts.push(format!("{}{suffix}", self.text(cur)));
                    parts.reverse();
                    return Some(parts.join("."));
                }
                "attribute" => {
                    let attr = cur.child_by_field_name("attribute")?;
                    parts.push(format!("{}{suffix}", self.text(attr)));
                    suffix.clear();
                    cur = cur.child_by_field_name("object")?;
                }
                "call" if calls => {
                    suffix.push_str("()");
                    cur = cur.child_by_field_name("function")?;
                }
                _ => return None,
            }
        }
        None
    }

    /// Resolved name of a call, for folding paths.
    fn callee(&self, call: Node) -> Option<String> {
        let f = call.child_by_field_name("function")?;
        let name = self.dotted(f, true)?;
        Some(
            self.core
                .resolve_best(&name, |n| is_path_builder(n) || last_segment(n) == "home"),
        )
    }

    /// Variable names bound by an assignment target.
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
                "identifier" => out.push(self.text(n).to_string()),
                "attribute" => out.extend(self.dotted(n, false)),
                "subscript" => stack.extend(n.child_by_field_name("value")),
                "pattern_list"
                | "tuple_pattern"
                | "list_pattern"
                | "parenthesized_expression"
                | "expression_list"
                | "tuple"
                | "list"
                | "list_splat_pattern"
                | "as_pattern_target" => {
                    stack.extend(self.core.children(n));
                }
                _ => {}
            }
        }
        out
    }

    fn bind(&mut self, targets: Vec<String>, rhs: Option<Node>, end: Option<usize>, line: u32) {
        let rhs_callee = rhs
            .filter(|r| r.kind() == "call")
            .and_then(|r| r.child_by_field_name("function"))
            .and_then(|f| self.dotted(f, true));
        self.core.bind(targets, rhs, end, line, rhs_callee);
    }

    /// First pass. Returns false when the time budget ran out.
    fn collect(&mut self, tree: &'t Tree) -> bool {
        let src = self.core.src;
        run_query(query(), tree, src, |kind, node| self.capture(kind, node))
    }

    fn capture(&mut self, kind: &str, node: Node<'t>) {
        let ln = line(node);
        match kind {
            "ident" => self.core.token(node, self.text(node).to_string(), true),
            "attr" => {
                if let Some(a) = node.child_by_field_name("attribute") {
                    self.core.not_values.insert(a.start_byte());
                }
                if let Some(d) = self.dotted(node, false) {
                    self.core.token(node, d, false);
                }
            }
            "kwarg" => {
                if let Some(n) = node.child_by_field_name("name") {
                    self.core.not_values.insert(n.start_byte());
                }
            }
            "str" => self.strings.push(node),
            "doc" => {
                self.docstrings.insert(node.start_byte());
            }
            "binop" => {
                let op = node.child_by_field_name("operator").map(|o| o.kind());
                if matches!(op, Some("+" | "/")) {
                    self.binops.push(node);
                }
            }
            "subscript" => self.subscripts.push(node),
            "call" => {
                let callee = node
                    .child_by_field_name("function")
                    .and_then(|f| self.dotted(f, true));
                let args = node.child_by_field_name("arguments");
                self.core.add_call(node, callee, args);
            }
            "assign" | "augassign" => {
                let Some(left) = node.child_by_field_name("left") else {
                    return;
                };
                if kind == "assign" && self.bind_pairs(left, node.child_by_field_name("right"), ln)
                {
                    return;
                }
                let targets = self.targets(left);
                let before = self.core.binds.len();
                self.bind(targets.clone(), node.child_by_field_name("right"), None, ln);
                if kind == "augassign"
                    && self.core.binds.len() > before
                    && let Some(b) = self.core.binds.last_mut()
                {
                    b.extra = targets;
                }
            }
            "walrus" => {
                let targets = node
                    .child_by_field_name("name")
                    .map(|n| self.targets(n))
                    .unwrap_or_default();
                self.bind(targets, node.child_by_field_name("value"), None, ln);
            }
            "for" => {
                let targets = node
                    .child_by_field_name("left")
                    .map(|n| self.targets(n))
                    .unwrap_or_default();
                let end = (node.kind() == "for_in_clause").then(|| node.end_byte());
                self.bind(targets, node.child_by_field_name("right"), end, ln);
            }
            "as" => {
                let targets = node
                    .child_by_field_name("alias")
                    .map(|n| self.targets(n))
                    .unwrap_or_default();
                let value = self.core.first_child(node);
                self.bind(targets, value, None, ln);
            }
            "func" => {
                if let Some(n) = node.child_by_field_name("name") {
                    self.core.not_values.insert(n.start_byte());
                    self.funcs.push((self.text(n).to_string(), node.end_byte()));
                }
            }
            "return" => {
                while self.funcs.last().is_some_and(|f| f.1 <= node.start_byte()) {
                    self.funcs.pop();
                }
                if let Some((name, _)) = self.funcs.last() {
                    let name = name.clone();
                    self.bind(vec![name], Some(node), None, ln);
                }
            }
            "import" => self.import(node),
            _ => {}
        }
    }

    /// `a, b = x, y`: binds each target to its own element. False when the
    /// sides are not sequences of the same length.
    fn bind_pairs(&mut self, left: Node, right: Option<Node>, line: u32) -> bool {
        let Some(right) = right else { return false };
        let seq_left = matches!(
            left.kind(),
            "pattern_list" | "tuple_pattern" | "list_pattern"
        );
        let seq_right = matches!(right.kind(), "expression_list" | "tuple" | "list");
        let count = left.named_child_count();
        if !seq_left || !seq_right || count != right.named_child_count() || count > 64 {
            return false;
        }
        let pairs: Vec<(Node, Node)> = (0..count as u32)
            .filter_map(|i| Some((left.named_child(i)?, right.named_child(i)?)))
            .collect();
        let splat = |n: &Node| n.kind().contains("splat");
        if pairs.len() != count || pairs.iter().any(|(l, r)| splat(l) || splat(r)) {
            return false;
        }
        for (l, r) in pairs {
            let targets = self.targets(l);
            self.bind(targets, Some(r), None, line);
        }
        true
    }

    fn import(&mut self, node: Node) {
        let module = node
            .child_by_field_name("module_name")
            .filter(|m| m.kind() == "dotted_name")
            .map(|m| self.text(m).to_string());
        if node.kind() == "import_from_statement" && module.is_none() {
            return;
        }
        let mut cursor = node.walk();
        let names: Vec<Node> = node.children_by_field_name("name", &mut cursor).collect();
        for n in names {
            let (name, alias) = match n.kind() {
                "aliased_import" => (
                    n.child_by_field_name("name").map(|x| self.text(x)),
                    n.child_by_field_name("alias").map(|x| self.text(x)),
                ),
                _ => (Some(self.text(n)), None),
            };
            let Some(name) = name else { continue };
            if module.is_none() && alias.is_none() {
                // `import a.b` binds `a` to module `a`: nothing to rename.
                continue;
            }
            let full = match &module {
                Some(m) => format!("{m}.{name}"),
                None => name.to_string(),
            };
            let local = alias.unwrap_or_else(|| name.split('.').next().unwrap_or(name));
            if local != full {
                self.core.add_alias(local, full, alias_relevant);
            }
        }
    }
}

impl<'t> Extract<'t> {
    /// Path text an expression builds from string literals, `/` and `+`,
    /// `os.path.join`, `Path(...)`, `joinpath` and `Path.home()`. Ids of the
    /// nodes it walked go into `visited`.
    fn fold(&self, node: Node<'t>, visited: &mut HashSet<usize>) -> String {
        let mut out = String::new();
        let mut stack = vec![FoldItem::Node(node)];
        let mut steps = 0;
        let push_children = |stack: &mut Vec<FoldItem<'t>>, n: Node<'t>, sep: bool| {
            for (i, c) in self
                .core
                .children_upto(n, MAX_FOLD_NODES)
                .into_iter()
                .enumerate()
                .rev()
            {
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
                self.core.truncate();
                break;
            }
            visited.insert(n.id());
            match n.kind() {
                "string" => out.push_str(string_content(self.text(n))),
                "binary_operator" => {
                    let parts = (
                        n.child_by_field_name("left"),
                        n.child_by_field_name("operator").map(|o| o.kind()),
                        n.child_by_field_name("right"),
                    );
                    if let (Some(l), Some(op @ ("+" | "/")), Some(r)) = parts {
                        stack.push(FoldItem::Node(r));
                        if op == "/" {
                            stack.push(FoldItem::Sep);
                        }
                        stack.push(FoldItem::Node(l));
                    }
                }
                "parenthesized_expression" | "concatenated_string" => {
                    push_children(&mut stack, n, false);
                }
                "call" => {
                    let name = self.callee(n).unwrap_or_default();
                    if is_path_builder(&name) {
                        if let Some(args) = n.child_by_field_name("arguments") {
                            push_children(&mut stack, args, true);
                        }
                        if last_segment(&name) == "joinpath" {
                            stack.push(FoldItem::Sep);
                            let recv = n
                                .child_by_field_name("function")
                                .and_then(|f| f.child_by_field_name("object"));
                            stack.extend(recv.map(FoldItem::Node));
                        }
                    } else if last_segment(&name) == "home" {
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
            if self.docstrings.contains(&s.start_byte()) {
                continue;
            }
            let raw = self.text(s);
            if let Some(class) = literal_source_class(raw) {
                let text = self
                    .core
                    .describe_in_call(s, string_content(raw), is_path_builder);
                self.core.add_source(s, class, text, None);
                spans.push((s.start_byte(), s.end_byte(), class));
            }
            if is_sensitive_write_path(raw) {
                self.core.add_sensitive(s);
                spans.push((s.start_byte(), s.end_byte(), SENSITIVE_WRITE));
            }
        }
        spans
    }

    /// Sources and sensitive paths assembled from several pieces. A candidate
    /// already walked by an enclosing fold is skipped; one the enclosing fold
    /// did not reach (inside an unrelated call) is folded on its own. A match
    /// is reported only when no single literal inside already matched.
    fn fold_sites(&mut self, spans: &[(usize, usize, &str)]) {
        let mut cands = std::mem::take(&mut self.binops);
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

    /// `os.environ["NAME"]` reads of secret-looking variables.
    fn env_subscripts(&mut self) {
        for s in std::mem::take(&mut self.subscripts) {
            let name = s
                .child_by_field_name("value")
                .and_then(|v| self.dotted(v, false))
                .and_then(|d| self.core.resolve_where(&d, |n| n == "os.environ"));
            if name.is_none() {
                continue;
            }
            let Some(key) = s
                .child_by_field_name("subscript")
                .filter(|k| k.kind() == "string")
            else {
                continue;
            };
            let key = string_content(self.text(key));
            if let Some(class) = env_class(key) {
                let text = format!("os.environ[{}]", clip(key, TEXT_CHARS));
                self.core.add_source(s, class, text, None);
            }
        }
    }

    /// `os.getenv("NAME")` and `os.environ.get("NAME")` style reads.
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

    /// Positional arguments (up to 8) and keyword arguments of a call.
    fn arguments(&self, args: Node<'t>) -> (Vec<Node<'t>>, Vec<(&'t str, Node<'t>)>) {
        let mut pos = Vec::new();
        let mut kw = Vec::new();
        for a in self.core.children(args) {
            if a.kind() == "keyword_argument" {
                if let (Some(k), Some(v)) = (
                    a.child_by_field_name("name"),
                    a.child_by_field_name("value"),
                ) {
                    kw.push((self.text(k), v));
                }
            } else if pos.len() < 8 {
                pos.push(a);
            }
        }
        (pos, kw)
    }

    fn is_write_mode(&self, mode: Option<Node>) -> bool {
        mode.filter(|m| m.kind() == "string")
            .is_some_and(|m| string_content(self.text(m)).contains(['w', 'a', 'x', '+']))
    }

    /// Whether a call writes to a path that a sensitive literal reaches.
    fn writes_sensitive(&self, c: &Call<'t>, name: &str, sensitive: &HashSet<String>) -> bool {
        let Some(args) = c.args.filter(|_| is_write_call(name)) else {
            return false;
        };
        let (pos, kw) = self.arguments(args);
        let kw = |k: &str| kw.iter().find(|(n, _)| *n == k).map(|(_, v)| *v);
        let last = last_segment(name);
        let path = if matches!(name, "open" | "io.open" | "codecs.open" | "builtins.open") {
            if !self.is_write_mode(pos.get(1).copied().or_else(|| kw("mode"))) {
                return false;
            }
            pos.first().copied().or_else(|| kw("file"))
        } else if name == "os.open" {
            let flags = pos.get(1).map_or("", |f| self.text(*f));
            let writes = ["O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT"]
                .iter()
                .any(|f| flags.contains(f));
            if !writes {
                return false;
            }
            pos.first().copied()
        } else if matches!(last, "write_text" | "write_bytes")
            || (last == "open"
                && name.contains('.')
                && self.is_write_mode(pos.first().copied().or_else(|| kw("mode"))))
        {
            c.node
                .child_by_field_name("function")
                .and_then(|f| f.child_by_field_name("object"))
        } else if name.starts_with("shutil.")
            && matches!(last, "copy" | "copy2" | "copyfile" | "copytree" | "move")
        {
            pos.get(1).copied().or_else(|| kw("dst"))
        } else {
            None
        };
        path.is_some_and(|p| self.core.node_refs(p).iter().any(|r| sensitive.contains(r)))
    }

    /// Whether an exec call runs a shell command that fetches with curl or
    /// wget and pipes the result into a shell.
    fn runs_fetch_pipe(&self, c: &Call<'t>, name: &str) -> bool {
        let Some(args) = c.args else {
            return false;
        };
        let (pos, kw) = self.arguments(args);
        let Some(first) = pos.first().copied() else {
            return false;
        };
        let shell_true = kw
            .iter()
            .any(|(k, v)| *k == "shell" && self.text(*v) == "True");
        let commands: Vec<String> = if matches!(name, "os.system" | "os.popen") || shell_true {
            self.command_text(first).into_iter().collect()
        } else if first.kind() == "list" {
            let items: Vec<String> = self
                .core
                .children(first)
                .into_iter()
                .filter_map(|n| self.command_text(n))
                .collect();
            let shell = items
                .iter()
                .any(|t| SHELLS.contains(&t.as_str()) || is_posix_shell(t));
            if shell && items.iter().any(|t| is_shell_flag(t)) {
                items
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        commands.iter().any(|t| pipes_download_to_shell(t))
    }

    /// Text of a command built from string literals and `+`. Other pieces
    /// stand in as an unknown character. `None` when no literal is involved.
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
                "concatenated_string" | "parenthesized_expression" => {
                    stack.extend(self.core.children_upto(n, MAX_FOLD_NODES).into_iter().rev());
                }
                "binary_operator"
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

    /// Every sink.
    fn call_sites(&mut self, sensitive: &HashSet<String>) -> Vec<Site> {
        let mut sinks = Vec::new();
        let mut connect = false;
        let mut first_dup: Option<usize> = None;
        let calls = std::mem::take(&mut self.core.calls);
        for (idx, c) in calls.iter().enumerate() {
            let Some(name) = c.callee.as_deref() else {
                continue;
            };
            if is_env_call(name) {
                continue;
            }
            connect |= is_connect(name);
            if first_dup.is_none() && matches!(name, "os.dup2" | "pty.spawn") {
                first_dup = Some(idx);
            }
            let class = match sink_class(name) {
                Some(EXEC) if self.runs_fetch_pipe(c, name) => Some(DOWNLOAD_EXEC),
                Some(class) => Some(class),
                None => self
                    .writes_sensitive(c, name, sensitive)
                    .then_some(SENSITIVE_WRITE),
            };
            let Some(class) = class else { continue };
            self.core
                .push_sink(&mut sinks, || self.core.sink(c, name, class, None));
        }
        if let (true, Some(i)) = (connect, first_dup) {
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
        let spans = self.literal_sites();
        self.fold_sites(&spans);
        self.env_subscripts();
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

fn is_env_call(name: &str) -> bool {
    matches!(
        name,
        "os.getenv" | "os.environ.get" | "os.environ.setdefault" | "os.environ.pop"
    )
}

/// Calls whose path argument `writes_sensitive` inspects.
fn is_write_call(name: &str) -> bool {
    let last = last_segment(name);
    matches!(
        name,
        "open" | "io.open" | "codecs.open" | "builtins.open" | "os.open"
    ) || matches!(last, "write_text" | "write_bytes")
        || (last == "open" && name.contains('.'))
        || (name.starts_with("shutil.")
            && matches!(last, "copy" | "copy2" | "copyfile" | "copytree" | "move"))
}

/// Names the rules classify: a call resolving to one of these is preferred
/// over its other possible meanings.
fn relevant(name: &str) -> bool {
    sink_class(name).is_some()
        || is_env_call(name)
        || is_connect(name)
        || is_path_builder(name)
        || is_write_call(name)
        || matches!(name, "os.dup2" | "pty.spawn")
}

/// Modules whose members the rules classify.
const RULE_MODULES: &[&str] = &[
    "requests",
    "httpx",
    "urllib3",
    "aiohttp",
    "urllib",
    "urllib2",
    "http",
    "socket",
    "smtplib",
    "ftplib",
    "subprocess",
    "os",
    "builtins",
    "pathlib",
    "shutil",
    "io",
    "codecs",
    "pty",
];

/// Whether an alias meaning matters to the rules: a classified name or a
/// module whose members are classified.
fn alias_relevant(full: &str) -> bool {
    let root = full.split(['.', '(']).next().unwrap_or("");
    relevant(full) || RULE_MODULES.contains(&root)
}
