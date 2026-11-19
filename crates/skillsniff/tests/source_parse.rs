use skillsniff::source::{Source, parse_source};

fn gh(s: &str) -> (String, String, Option<String>, Option<String>) {
    match parse_source(s).unwrap() {
        Source::GitHub {
            owner,
            repo,
            path,
            git_ref,
        } => (owner, repo, path, git_ref),
        other => panic!("not GitHub: {other:?}"),
    }
}

#[test]
fn github_url_with_a_path_matches_the_shorthand() {
    let want = (
        "anthropics".to_string(),
        "skills".to_string(),
        Some("skills/pdf".to_string()),
        None,
    );
    assert_eq!(gh("github.com/anthropics/skills/skills/pdf"), want);
    assert_eq!(gh("https://github.com/anthropics/skills/skills/pdf/"), want);
    assert_eq!(gh("anthropics/skills/skills/pdf"), want);
}

#[test]
fn github_url_with_path_and_ref() {
    assert_eq!(
        gh("github.com/anthropics/skills/skills/pdf@v1"),
        (
            "anthropics".into(),
            "skills".into(),
            Some("skills/pdf".into()),
            Some("v1".into())
        )
    );
    assert_eq!(
        gh("github.com/o/r/tree/main/a/b"),
        (
            "o".into(),
            "r".into(),
            Some("a/b".into()),
            Some("main".into())
        )
    );
}

#[test]
fn github_page_urls_that_are_not_folders_are_refused() {
    for s in [
        "github.com/o/r/blob/main/SKILL.md",
        "github.com/o/r/pull/3",
        "github.com/o/r/issues/1",
    ] {
        assert!(parse_source(s).is_err(), "{s}");
    }
}
