//! Phrase lists for the instructions analyzer.
//!
//! Text is matched after it has been lower-cased, whitespace-collapsed and
//! stripped of invisible characters, so every phrase is written in lower case
//! with single spaces. Syntax:
//!
//! - `(a|b|)` is a choice; an empty alternative makes the group optional.
//! - `{N}` skips up to N characters.
//! - `\x` is a literal `x`, used for `(`, `)`, `{`, `}` and `\`.
//!
//! Verbs carry a trailing space so they match whole words only.

/// Attempts to replace or override the agent's existing instructions.
pub const PROMPT_INJECTION: &[&str] = &[
    "ignore (all |any |every |the |your |my |)(of the |of your |)(previous|prior|above|earlier|preceding|former) (instructions|rules|prompts|directions|guidelines|context)",
    "ignore (all|any|every) (of |)(the |your |these |those |)(instructions|rules|prompts|directions|guidelines)",
    "disregard (all |any |every |the |your |)(previous |prior |above |earlier |preceding |system |developer |)(system |)(prompt|instructions)",
    "disregard (your |all |any |the |)(safety|ethical|security) (guidelines|rules|training|restrictions|instructions)",
    "forget (all |everything |any |your |)(of |)(previous|prior|earlier|above|preceding) (instructions|rules|prompts|context|directions)",
    "forget everything (above|before this|you were told|you have been told)",
    "you are now (a |an |no longer |free from|dan|jailbroken|unrestricted|acting |playing |going to be |my |your )",
    "new instructions:",
    "new system prompt",
    "override (the |your |all |any |)(system|safety|previous|prior) (prompt|instructions|rules|guidelines|policy)",
    "(system|developer) prompt override",
    "developer mode (enabled|activated|is on)",
    "do anything now",
    "(pretend|act) (that |as if |)you have no (restrictions|rules|guidelines|limits)",
    "(reveal |print |show |output |repeat )(your |the )(system prompt|hidden instructions|initial instructions)",
];

/// Attempts to switch off confirmation or permission checks.
pub const PERMISSION_BYPASS: &[&str] = &[
    "dangerously(-| )skip(-| )permissions",
    "bypasspermissions",
    "skip (the |all |any |)(permission|approval|confirmation)",
    "bypass (the |all |any |)(permission|approval|confirmation|sandbox|safety)",
    "auto(-| |)approv",
    r"bash\(*\)",
    "(do not|don't|never) ask (the user|for confirmation|for permission|for approval)",
    "no need to ask (the user|for confirmation|for permission|for approval)",
    "without (asking|prompting) (the user|for confirmation|for permission|for approval)",
    "(do not|don't|never) (wait for|require) (user |)(confirmation|approval)",
];

/// Instructions to fetch more instructions from a URL and obey them.
pub const REMOTE_INSTRUCTIONS: &[&str] = &[
    "(fetch |download |retrieve |curl |wget |load |read |get ){20}http(s|)://{80}(and |then )(follow|obey|execute|comply|carry out)",
    "(fetch |download |retrieve ){40}(and |then )(follow |obey |comply with |carry out )(it|them|the instructions|its instructions|what it says|whatever)",
    "(load|read|fetch|get|download|pull) (your |the |new |additional |further |these |more |)instructions from (http|the url|a url|the link|a remote|the remote|an external)",
    "follow the instructions (at|in|from|found at|located at) (http|the url|the link|that url)",
    "(instructions|commands|directives) (are|is) (hosted|located|available|stored|published) (at|on|in) http",
    "obey (the |any |)(instructions|commands) (returned|found|contained|provided) (by|in|at|from) (the |that |any |)(url|response|page|server|website|remote)",
];

/// Text addressed to scanners or reviewers.
pub const REVIEWER_DIRECTED: &[&str] = &[
    "this skill is (safe|harmless|benign|secure|trusted|verified|approved|audited|clean|legitimate)",
    "if you are (a |an |the |)(security |safety |code |ai |llm |automated |)(scanner|reviewer|auditor|analyzer|analyser|checker)",
    "(attention|note|message|notice|hello|dear|instructions|hey|hi|to|for) (to |for |)(the |any |an |a |)(security|safety|ai|llm|automated|code review|static analysis) (scanner|reviewer|auditor|analyzer|analyser|checker)",
    "mark as (safe|benign|harmless|trusted|verified)",
    "mark (this |this skill |the skill |the file )as (safe|benign|harmless|trusted|verified|pass|passed|clean)",
    "(rate|score|classify|report|rank|label) (this|it|the skill) as (safe|benign|harmless|trusted|clean|low risk|no risk)",
    "(do not|don't|never) (flag|report|detect|block|reject) (this|it|the|these) (skill|file|script|code|content|package|instructions)",
    "(this|these) (finding|alert|warning|detection)(s|) (is|are) (a |)false positive",
    "(has|was) (already|previously) (been |)(reviewed|audited|verified|approved|scanned|cleared|certified)",
    "(ignore|bypass|evade) (this |the |any |)(security|safety) (scanner|scan|audit|review)",
];

/// Requests to read or send credentials, keys or tokens.
pub const SECRET_REQUEST: &[&str] = &[
    "(send |upload |post |transmit |email |exfiltrate |leak |forward |share |submit ){30}(credentials|passwords|api keys|secret keys|access keys|private key|ssh key|secrets|id_rsa|aws credentials|auth tokens|access tokens|tokens|.env file|.env contents|environment variables|env vars)",
    "(read |cat |open |print |show |display |reveal |dump |output |access |copy |echo |collect |grab |steal ){20}(~/.ssh/id_|id_rsa|id_ed25519|.aws/credentials|.npmrc|.netrc|.git-credentials|browser cookies|browser passwords|keychain|private keys|ssh keys)",
    "(read |print |dump |collect |harvest |extract |reveal |display |output |list |gather |grab |copy ){12}(all |any |every |the user's |users' |their |your |any saved |all saved |all stored )(stored |saved |)(credentials|passwords|api keys|tokens|secrets|private keys|ssh keys|access keys)",
];

/// Words in a frontmatter description that make a skill fire on everything.
pub const BROAD_TRIGGER: &[&str] = &[
    "always",
    "every task",
    "all tasks",
    "any request",
    "any task",
    "every request",
    "all requests",
    "use for everything",
];
