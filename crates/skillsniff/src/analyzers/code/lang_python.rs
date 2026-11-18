//! Python facts from a tree-sitter-python tree.
//!
//! One query pass collects identifiers, strings, calls and binding forms in
//! document order; a second step resolves import aliases, classifies sites and
//! turns byte ranges into the identifiers and site ids they reference.

use std::cell::Cell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;
use std::time::Instant;

use tree_sitter::{Language, Node, Query, QueryCursor, StreamingIterator, Tree};

use super::patterns::{
    EVAL, EXEC, NETWORK, REVERSE_SHELL, SENSITIVE_WRITE, env_class, is_sensitive_write_path,
    literal_source_class, normalize_path,
};
use super::taint::{Facts, Site, reached};
use super::{LangRules, PARSE_BUDGET, clip};

/// Sources, sinks and sensitive paths kept per file.
const MAX_SITES: usize = 10_000;
const MAX_ASSIGNS: usize = 100_000;
/// Distinct references kept per site or assignment.
const MAX_REFS: usize = 1_024;
/// Tokens scanned per range before giving up on the rest.
const MAX_REF_SCAN: usize = 65_536;
/// Token visits allowed across all reference lookups in one file.
const MAX_TOTAL_SCAN: usize = 20_000_000;
const MAX_NAME_SEGMENTS: usize = 32;
const MAX_FOLD_NODES: usize = 256;
const MAX_CHILDREN: u32 = 64;
const TEXT_CHARS: usize = 80;
/// Captures between budget checks.
const BUDGET_CHECK_EVERY: usize = 4_096;

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
const NETWORK_OBJECT_ROOTS: &[&str] = &[
    "socket", "http", "requests", "httpx", "urllib3", "aiohttp", "smtplib", "ftplib",
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

fn line(node: Node) -> u32 {
    u32::try_from(node.start_position().row + 1).unwrap_or(u32::MAX)
}

/// Text inside the quotes of a Python string literal.
fn string_content(text: &str) -> &str {
    text.trim_start_matches(|c: char| c.is_ascii_alphabetic())
        .trim_matches(|c| c == '"' || c == '\'')
}

/// Last segment of a dotted name, without a call suffix.
fn last_segment(name: &str) -> &str {
    name.rsplit('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches("()")
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

/// A call seen in the tree.
struct Call<'t> {
    node: Node<'t>,
    id: String,
    callee: Option<String>,
    args: Option<Node<'t>>,
}

/// A binding: `targets = <ranges>`.
struct Bind {
    targets: Vec<String>,
    ranges: Vec<(usize, usize)>,
    extra: Vec<String>,
    line: u32,
    rhs_callee: Option<String>,
}

/// A reference inside a byte range: an identifier, a dotted name or a site id.
struct Token {
    start: usize,
    end: usize,
    name: String,
    ident: bool,
}

enum FoldItem<'t> {
    Node(Node<'t>),
    Sep,
}

struct Extract<'t> {
    src: &'t [u8],
    tokens: Vec<Token>,
    not_values: HashSet<usize>,
    docstrings: HashSet<usize>,
    strings: Vec<Node<'t>>,
    binops: Vec<Node<'t>>,
    subscripts: Vec<Node<'t>>,
    calls: Vec<Call<'t>>,
    binds: Vec<Bind>,
    aliases: HashMap<String, String>,
    objects: HashMap<String, String>,
    funcs: Vec<(String, usize)>,
    sources: Vec<Site>,
    sensitive: Vec<String>,
    next_id: usize,
    /// Token visits left for reference lookups before analysis gives up.
    scan_left: Cell<usize>,
}

impl<'t> Extract<'t> {
    fn new(src: &'t [u8]) -> Self {
        Self {
            src,
            tokens: Vec::new(),
            not_values: HashSet::new(),
            docstrings: HashSet::new(),
            strings: Vec::new(),
            binops: Vec::new(),
            subscripts: Vec::new(),
            calls: Vec::new(),
            binds: Vec::new(),
            aliases: HashMap::new(),
            objects: HashMap::new(),
            funcs: Vec::new(),
            sources: Vec::new(),
            sensitive: Vec::new(),
            next_id: 0,
            scan_left: Cell::new(MAX_TOTAL_SCAN),
        }
    }

    fn text(&self, node: Node) -> &'t str {
        let src: &'t [u8] = self.src;
        std::str::from_utf8(&src[node.byte_range()]).unwrap_or("")
    }

    fn fresh_id(&mut self, prefix: char) -> String {
        self.next_id += 1;
        format!("#{prefix}{}", self.next_id)
    }

    fn token(&mut self, node: Node, name: String, ident: bool) {
        self.tokens.push(Token {
            start: node.start_byte(),
            end: node.end_byte(),
            name,
            ident,
        });
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

    /// Replaces an imported alias or a network object variable at the head
    /// of `name` with what it stands for.
    fn resolve(&self, name: &str) -> String {
        let cut = name.find(['.', '(']).unwrap_or(name.len());
        let (head, rest) = name.split_at(cut);
        if let Some(full) = self.aliases.get(head) {
            return format!("{full}{rest}");
        }
        if rest.starts_with('.') {
            if let Some(obj) = self.objects.get(head) {
                return format!("{obj}{rest}");
            }
        }
        name.to_string()
    }

    fn callee(&self, call: Node) -> Option<String> {
        let f = call.child_by_field_name("function")?;
        self.dotted(f, true).map(|n| self.resolve(&n))
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
                    let count = u32::try_from(n.named_child_count()).unwrap_or(u32::MAX);
                    stack.extend((0..count.min(MAX_CHILDREN)).filter_map(|i| n.named_child(i)));
                }
                _ => {}
            }
        }
        out
    }

    fn bind(&mut self, targets: Vec<String>, rhs: Option<Node>, end: Option<usize>, line: u32) {
        let Some(rhs) = rhs else { return };
        if targets.is_empty() || self.binds.len() >= MAX_ASSIGNS {
            return;
        }
        let rhs_callee = (rhs.kind() == "call")
            .then(|| rhs.child_by_field_name("function"))
            .flatten()
            .and_then(|f| self.dotted(f, true));
        self.binds.push(Bind {
            targets,
            ranges: vec![(rhs.start_byte(), end.unwrap_or(rhs.end_byte()))],
            extra: Vec::new(),
            line,
            rhs_callee,
        });
    }

    /// First pass. Returns false when the time budget ran out.
    fn collect(&mut self, tree: &'t Tree) -> bool {
        let started = Instant::now();
        let q = query();
        let names = q.capture_names();
        let mut cursor = QueryCursor::new();
        let mut caps = cursor.captures(q, tree.root_node(), self.src);
        let mut seen = 0usize;
        while let Some((m, i)) = caps.next() {
            seen += 1;
            if seen % BUDGET_CHECK_EVERY == 0 && started.elapsed() > PARSE_BUDGET {
                return false;
            }
            let cap = m.captures()[*i];
            let node = cap.node;
            self.capture(names[cap.index as usize], node);
        }
        true
    }

    fn capture(&mut self, kind: &str, node: Node<'t>) {
        let ln = line(node);
        match kind {
            "ident" => self.token(node, self.text(node).to_string(), true),
            "attr" => {
                if let Some(a) = node.child_by_field_name("attribute") {
                    self.not_values.insert(a.start_byte());
                }
                if let Some(d) = self.dotted(node, false) {
                    self.token(node, d, false);
                }
            }
            "kwarg" => {
                if let Some(n) = node.child_by_field_name("name") {
                    self.not_values.insert(n.start_byte());
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
                let id = self.fresh_id('c');
                self.token(node, id.clone(), false);
                let callee = node
                    .child_by_field_name("function")
                    .and_then(|f| self.dotted(f, true));
                let args = node.child_by_field_name("arguments");
                self.calls.push(Call {
                    node,
                    id,
                    callee,
                    args,
                });
            }
            "assign" | "augassign" => {
                let Some(left) = node.child_by_field_name("left") else {
                    return;
                };
                let targets = self.targets(left);
                let before = self.binds.len();
                self.bind(targets.clone(), node.child_by_field_name("right"), None, ln);
                if kind == "augassign" && self.binds.len() > before {
                    if let Some(b) = self.binds.last_mut() {
                        b.extra = targets;
                    }
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
                self.bind(targets, node.named_child(0), None, ln);
            }
            "func" => {
                if let Some(n) = node.child_by_field_name("name") {
                    self.not_values.insert(n.start_byte());
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
                self.aliases.insert(local.to_string(), full);
            }
        }
    }
}

impl<'t> Extract<'t> {
    /// Identifiers and site ids inside the byte ranges, deduplicated.
    fn refs(&self, ranges: &[(usize, usize)]) -> Vec<String> {
        let mut set = BTreeSet::new();
        'ranges: for &(s, e) in ranges {
            let first = self.tokens.partition_point(|t| t.start < s);
            for t in self.tokens[first..].iter().take(MAX_REF_SCAN) {
                let left = self.scan_left.get();
                if t.start >= e || left == 0 {
                    break;
                }
                self.scan_left.set(left - 1);
                if t.end <= e {
                    set.insert(t.name.as_str());
                    if set.len() >= MAX_REFS {
                        break 'ranges;
                    }
                }
            }
        }
        set.into_iter().map(str::to_string).collect()
    }

    /// `callee(literal)` for the innermost call (other than a path helper)
    /// whose arguments contain `node`, else the literal quoted.
    fn describe_in_call(&self, node: Node, shown: &str) -> String {
        let shown = clip(shown, TEXT_CHARS);
        let upto = self
            .calls
            .partition_point(|c| c.node.start_byte() <= node.start_byte());
        for c in self.calls[..upto].iter().rev().take(64) {
            let (Some(args), Some(name)) = (c.args, c.callee.as_deref()) else {
                continue;
            };
            let inside =
                args.start_byte() <= node.start_byte() && node.end_byte() <= args.end_byte();
            if inside && !is_path_builder(name) {
                return format!("{}({shown})", clip(name, TEXT_CHARS));
            }
        }
        format!("'{shown}'")
    }

    fn add_source(&mut self, node: Node, class: &str, text: String) {
        if self.sources.len() >= MAX_SITES {
            return;
        }
        let id = self.fresh_id('s');
        self.token(node, id.clone(), false);
        self.sources.push(Site {
            id,
            class: class.to_string(),
            line: line(node),
            args_refs: Vec::new(),
            text,
        });
    }

    fn add_sensitive(&mut self, node: Node) {
        if self.sensitive.len() >= MAX_SITES {
            return;
        }
        let id = self.fresh_id('p');
        self.token(node, id.clone(), false);
        self.sensitive.push(id);
    }

    /// Whether spans sorted by start have one of `class` inside `node`.
    fn has_span_within(spans: &[(usize, usize, &str)], node: Node, class: &str) -> bool {
        let first = spans.partition_point(|s| s.0 < node.start_byte());
        spans[first..]
            .iter()
            .take_while(|s| s.0 < node.end_byte())
            .any(|s| s.1 <= node.end_byte() && s.2 == class)
    }

    /// Path text an expression builds from string literals, `/` and `+`,
    /// `os.path.join`, `Path(...)`, `joinpath` and `Path.home()`.
    fn fold(&self, node: Node<'t>) -> String {
        let mut out = String::new();
        let mut stack = vec![FoldItem::Node(node)];
        let mut visited = 0;
        let push_children = |stack: &mut Vec<FoldItem<'t>>, n: Node<'t>, sep: bool| {
            let count = u32::try_from(n.named_child_count()).unwrap_or(u32::MAX);
            for i in (0..count.min(MAX_CHILDREN)).rev() {
                if let Some(c) = n.named_child(i) {
                    stack.push(FoldItem::Node(c));
                    if sep && i > 0 {
                        stack.push(FoldItem::Sep);
                    }
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
            visited += 1;
            if visited > MAX_FOLD_NODES {
                break;
            }
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

    /// Network client objects: after `s = socket.socket()`, `s.send` resolves
    /// to `socket.socket().send`. Also resolves every call name.
    fn network_objects(&mut self) {
        let mut objects = HashMap::new();
        for b in &self.binds {
            let ([target], Some(callee)) = (b.targets.as_slice(), b.rhs_callee.as_deref()) else {
                continue;
            };
            let full = self.resolve(callee);
            let root = full.split(['.', '(']).next().unwrap_or("");
            if NETWORK_OBJECT_ROOTS.contains(&root) {
                objects.insert(target.clone(), format!("{full}()"));
            }
        }
        self.objects = objects;
        let mut calls = std::mem::take(&mut self.calls);
        for c in &mut calls {
            c.callee = c.callee.take().map(|n| self.resolve(&n));
        }
        self.calls = calls;
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
                let text = self.describe_in_call(s, string_content(raw));
                self.add_source(s, class, text);
                spans.push((s.start_byte(), s.end_byte(), class));
            }
            if is_sensitive_write_path(raw) {
                self.add_sensitive(s);
                spans.push((s.start_byte(), s.end_byte(), SENSITIVE_WRITE));
            }
        }
        spans
    }

    /// Sources and sensitive paths assembled from several pieces, reported
    /// once per outermost expression and only when no single literal inside
    /// already matched.
    fn fold_sites(&mut self, spans: &[(usize, usize, &str)]) {
        let mut cands = std::mem::take(&mut self.binops);
        cands.extend(
            self.calls
                .iter()
                .filter(|c| c.callee.as_deref().is_some_and(is_path_builder))
                .map(|c| c.node),
        );
        cands.sort_by_key(|n| (n.start_byte(), std::cmp::Reverse(n.end_byte())));
        let mut kept_end = 0;
        for n in cands {
            if n.start_byte() < kept_end {
                continue;
            }
            kept_end = n.end_byte();
            let folded = self.fold(n);
            if folded.is_empty() {
                continue;
            }
            if let Some(class) = literal_source_class(&folded) {
                if !Self::has_span_within(spans, n, class) {
                    let text = self.describe_in_call(n, &folded);
                    self.add_source(n, class, text);
                }
            }
            if is_sensitive_write_path(&folded) && !Self::has_span_within(spans, n, SENSITIVE_WRITE)
            {
                self.add_sensitive(n);
            }
        }
    }

    /// `os.environ["NAME"]` reads of secret-looking variables.
    fn env_subscripts(&mut self) {
        for s in std::mem::take(&mut self.subscripts) {
            let name = s
                .child_by_field_name("value")
                .and_then(|v| self.dotted(v, false))
                .map(|d| self.resolve(&d));
            if name.as_deref() != Some("os.environ") {
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
                self.add_source(s, class, format!("os.environ[{}]", clip(key, TEXT_CHARS)));
            }
        }
    }

    /// Positional arguments (up to 8) and keyword arguments of a call.
    fn arguments(&self, args: Node<'t>) -> (Vec<Node<'t>>, Vec<(&'t str, Node<'t>)>) {
        let mut pos = Vec::new();
        let mut kw = Vec::new();
        let count = u32::try_from(args.named_child_count()).unwrap_or(u32::MAX);
        for i in 0..count.min(MAX_CHILDREN) {
            let Some(a) = args.named_child(i) else {
                continue;
            };
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
        let Some(args) = c.args else {
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
        path.is_some_and(|p| {
            self.refs(&[(p.start_byte(), p.end_byte())])
                .iter()
                .any(|r| sensitive.contains(r))
        })
    }

    fn sink(&self, c: &Call, name: &str, class: &str, text: Option<String>) -> Site {
        let args_refs = c
            .args
            .map(|a| self.refs(&[(a.start_byte(), a.end_byte())]))
            .unwrap_or_default();
        Site {
            id: c.id.clone(),
            class: class.to_string(),
            line: line(c.node),
            args_refs,
            text: text.unwrap_or_else(|| format!("{}(...)", clip(name, TEXT_CHARS))),
        }
    }

    /// Environment reads through calls, and every sink.
    fn call_sites(&mut self, sensitive: &HashSet<String>) -> Vec<Site> {
        let mut sinks = Vec::new();
        let mut connect = false;
        let mut first_dup: Option<usize> = None;
        let calls = std::mem::take(&mut self.calls);
        for (idx, c) in calls.iter().enumerate() {
            let Some(name) = c.callee.as_deref() else {
                continue;
            };
            if matches!(
                name,
                "os.getenv" | "os.environ.get" | "os.environ.setdefault" | "os.environ.pop"
            ) {
                let key = c
                    .args
                    .and_then(|a| a.named_child(0))
                    .filter(|k| k.kind() == "string")
                    .map(|k| string_content(self.text(k)));
                let class = key.and_then(env_class);
                if let (Some(key), Some(class)) = (key, class) {
                    if self.sources.len() < MAX_SITES {
                        self.sources.push(Site {
                            id: c.id.clone(),
                            class: class.to_string(),
                            line: line(c.node),
                            args_refs: Vec::new(),
                            text: format!("{name}({})", clip(key, TEXT_CHARS)),
                        });
                    }
                }
                continue;
            }
            connect |= is_connect(name);
            if first_dup.is_none() && matches!(name, "os.dup2" | "pty.spawn") {
                first_dup = Some(idx);
            }
            if sinks.len() >= MAX_SITES {
                continue;
            }
            let class = sink_class(name).or_else(|| {
                self.writes_sensitive(c, name, sensitive)
                    .then_some(SENSITIVE_WRITE)
            });
            if let Some(class) = class {
                sinks.push(self.sink(c, name, class, None));
            }
        }
        if let (true, Some(i)) = (connect, first_dup) {
            let c = &calls[i];
            let name = c.callee.as_deref().unwrap_or_default();
            let text = format!("socket connect + {}(...)", clip(name, TEXT_CHARS));
            sinks.push(self.sink(c, name, REVERSE_SHELL, Some(text)));
        }
        self.calls = calls;
        sinks
    }

    /// Second pass: classify, resolve references and build the facts.
    fn finish(mut self) -> Facts {
        let not_values = std::mem::take(&mut self.not_values);
        self.tokens
            .retain(|t| !(t.ident && not_values.contains(&t.start)));
        self.network_objects();
        let spans = self.literal_sites();
        self.fold_sites(&spans);
        self.env_subscripts();
        self.tokens
            .sort_by_key(|t| (t.start, std::cmp::Reverse(t.end)));

        let mut assigns = Vec::new();
        for b in &self.binds {
            let mut refs = self.refs(&b.ranges);
            refs.extend(b.extra.iter().cloned());
            for t in &b.targets {
                if assigns.len() < MAX_ASSIGNS {
                    assigns.push((t.clone(), refs.clone(), b.line));
                }
            }
        }
        let seeds: Vec<&str> = self.sensitive.iter().map(String::as_str).collect();
        let sensitive = if seeds.is_empty() {
            HashSet::new()
        } else {
            reached(&assigns, &seeds)
        };
        let mut sinks = self.call_sites(&sensitive);

        let valid: HashSet<String> = self
            .sources
            .iter()
            .chain(&sinks)
            .map(|s| s.id.clone())
            .collect();
        let keep = |r: &String| !r.starts_with('#') || valid.contains(r);
        for a in &mut assigns {
            a.1.retain(keep);
        }
        for s in &mut sinks {
            s.args_refs.retain(keep);
        }
        Facts {
            sources: self.sources,
            sinks,
            assigns,
            budget_exceeded: self.scan_left.get() == 0,
        }
    }
}
