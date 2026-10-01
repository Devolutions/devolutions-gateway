//! Package identifier matching.

use std::borrow::Cow;

use now_policy::{Decision, PackageIdentifierCondition};
use now_policy_api::ManagerName;

use super::wildcard::wildcard_match_with_case;

/// Whether a rule's package identifier condition matches the requested identifier.
///
/// Identifiers and patterns are compared in their [`canonical_identifier`] form, so pattern
/// letter case is significant exactly when the manager distinguishes it.
/// Deny rules fail closed: they ignore letter case for every manager, also match the
/// [`embedded_package_names`] of decorated identifiers, and match every identifier whose
/// registry identity is unknown (see [`has_unknown_identity`]).
pub(super) fn package_identifiers_match(
    manager: ManagerName,
    value: &str,
    condition: Option<&PackageIdentifierCondition>,
    decision: Decision,
) -> bool {
    let Some(condition) = condition else {
        return true;
    };

    if decision == Decision::Deny && has_unknown_identity(manager, value) {
        return true;
    }

    let mut candidates = vec![identifier_key(manager, value, decision)];
    if decision == Decision::Deny {
        candidates.extend(
            embedded_package_names(manager, value)
                .into_iter()
                .map(|name| identifier_key(manager, name, decision)),
        );
    }

    match condition {
        PackageIdentifierCondition::Exact(identifiers) => identifiers.iter().any(|identifier| {
            let identifier = identifier_key(manager, identifier.as_ref(), decision);
            candidates.contains(&identifier)
        }),
        PackageIdentifierCondition::Patterns(patterns) => {
            patterns.is_empty()
                || patterns.iter().any(|pattern| {
                    let pattern = identifier_key(manager, pattern.as_ref(), decision);
                    candidates
                        .iter()
                        .any(|candidate| wildcard_match_with_case(candidate, &pattern, decision == Decision::Deny))
                })
        }
    }
}

/// Whether npm or Bun may resolve the identifier from a Git repository, URL or path rather than
/// from the registry, so its package identity is unknown before execution.
///
/// This covers URLs (`git+https://...`), GitHub shorthand (`owner/repo`), Git references (`#v1`),
/// Bun protocols other than `npm:` (`github:`, `file:`), and any embedded name that is not a
/// registry name (`name` or `@scope/name`).
fn has_unknown_identity(manager: ManagerName, identifier: &str) -> bool {
    // npm registry names are `name` or `@scope/name` and cannot start with `.` or `_`.
    let is_registry_name = |name: &str| {
        let (scope_is_valid, base) = match name.strip_prefix('@') {
            Some(scoped) => match scoped.split_once('/') {
                Some((scope, base)) => (!scope.is_empty(), base),
                None => (false, scoped),
            },
            None => (true, name),
        };
        scope_is_valid && !base.is_empty() && !base.contains('/') && !base.starts_with(['.', '_'])
    };

    match manager {
        ManagerName::Npm | ManagerName::Bun => {
            identifier.contains(['#', '\\'])
                || identifier.contains("://")
                || (manager == ManagerName::Bun
                    && identifier.split_once(':').is_some_and(|(prefix, _)| {
                        let protocol = prefix
                            .rfind('@')
                            .filter(|index| *index > 0)
                            .map_or(prefix, |index| &prefix[index + 1..]);
                        !protocol.eq_ignore_ascii_case("npm")
                    }))
                || !embedded_package_names(manager, identifier)
                    .into_iter()
                    .all(is_registry_name)
        }
        _ => false,
    }
}

/// Package names embedded in a decorated identifier.
///
/// - npm aliases (`alias:@scope/target@1.0.0`) name both the alias and the target package.
/// - Bun specifiers (`alias@npm:target`, `npm:target`, `github:owner/repo#v1`) name the optional alias
///   before the protocol and the target after it, without a `#ref`; the protocol itself is not a package name.
/// - vcpkg qualifies a port with features and a triplet (`port[feature]:triplet`).
/// - Other managers may accept a versioned specifier (`name@1.2.3`).
///
/// A leading `@` is kept as part of an npm scope.
pub(super) fn embedded_package_names(manager: ManagerName, identifier: &str) -> Vec<&str> {
    match manager {
        ManagerName::Npm => identifier.split(':').map(strip_version_suffix).collect(),
        ManagerName::Bun => match identifier.split_once(':') {
            None => vec![strip_version_suffix(identifier)],
            Some((prefix, target)) => {
                let alias = prefix
                    .rfind('@')
                    .filter(|index| *index > 0)
                    .map(|index| &prefix[..index]);
                alias.into_iter().chain([strip_version_suffix(target)]).collect()
            }
        },
        ManagerName::Vcpkg => vec![identifier.split(['[', ':']).next().unwrap_or(identifier)],
        _ => vec![strip_version_suffix(identifier)],
    }
}

/// Strip a `#ref` Git reference and an `@version` suffix, keeping a leading `@` scope.
fn strip_version_suffix(specifier: &str) -> &str {
    let specifier = specifier
        .split_once('#')
        .map_or(specifier, |(specifier, _reference)| specifier);
    specifier
        .rfind('@')
        .filter(|index| *index > 0)
        .map_or(specifier, |index| &specifier[..index])
}

/// Whether a decorated identifier may also select a package version, such as `name@1.2.3` or a
/// Git reference (`owner/repo#v1`).
pub(super) fn identifier_may_select_version(identifier: &str) -> bool {
    identifier.contains('#')
        || identifier
            .split(':')
            .any(|segment| segment.rfind('@').is_some_and(|index| index > 0))
}

fn identifier_key(manager: ManagerName, identifier: &str, decision: Decision) -> Cow<'_, str> {
    let canonical = canonical_identifier(manager, identifier);
    match decision {
        Decision::Allow => canonical,
        Decision::Deny => Cow::Owned(canonical.to_ascii_lowercase()),
    }
}

/// Canonical form of a package identifier under the package manager's own name equivalence.
///
/// Identifiers with the same canonical form select the same package:
/// - pip normalizes names per PEP 503: letter case is ignored and runs of `-`, `_` and `.` are equivalent.
/// - Cargo (crates.io) ignores letter case and treats `-` and `_` as equivalent.
/// - PowerShell repositories, Chocolatey, NuGet (`dotnet tool`), Scoop and vcpkg ignore letter case.
/// - WinGet identifiers are compared ignoring letter case. The broker passes `--exact`, so
///   WinGet itself requires the exact case and a case variant cannot select another package.
///
/// npm and Bun identifiers are case-sensitive because legacy mixed-case names are distinct packages.
pub(super) fn canonical_identifier(manager: ManagerName, identifier: &str) -> Cow<'_, str> {
    match manager {
        ManagerName::Pip => Cow::Owned(pep503_normalize(identifier)),
        ManagerName::Cargo => Cow::Owned(identifier.to_ascii_lowercase().replace('_', "-")),
        ManagerName::Winget
        | ManagerName::PowerShell
        | ManagerName::PowerShell7
        | ManagerName::Chocolatey
        | ManagerName::Dotnet
        | ManagerName::Scoop
        | ManagerName::Vcpkg => Cow::Owned(identifier.to_ascii_lowercase()),
        ManagerName::Npm
        | ManagerName::Bun
        | ManagerName::Apt
        | ManagerName::Dnf
        | ManagerName::Flatpak
        | ManagerName::Homebrew
        | ManagerName::Pacman
        | ManagerName::Snap => Cow::Borrowed(identifier),
    }
}

fn pep503_normalize(identifier: &str) -> String {
    let mut normalized = String::with_capacity(identifier.len());
    let mut previous_was_separator = false;

    for character in identifier.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !previous_was_separator {
                normalized.push('-');
            }
            previous_was_separator = true;
        } else {
            normalized.push(character.to_ascii_lowercase());
            previous_was_separator = false;
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use now_policy::{PackageIdentifier, StringPattern};

    use super::*;

    fn exact(identifiers: &[&str]) -> PackageIdentifierCondition {
        PackageIdentifierCondition::Exact(
            identifiers
                .iter()
                .map(|identifier| PackageIdentifier::parse(identifier).expect("valid identifier"))
                .collect::<BTreeSet<_>>(),
        )
    }

    fn patterns(patterns: &[&str]) -> PackageIdentifierCondition {
        PackageIdentifierCondition::Patterns(
            patterns
                .iter()
                .map(|pattern| StringPattern((*pattern).to_owned()))
                .collect(),
        )
    }

    fn matches(manager: ManagerName, value: &str, condition: &PackageIdentifierCondition, decision: Decision) -> bool {
        package_identifiers_match(manager, value, Some(condition), decision)
    }

    #[test]
    fn canonical_identifiers_follow_manager_name_equivalence() {
        assert_eq!(canonical_identifier(ManagerName::Pip, "Foo__Bar.-baz"), "foo-bar-baz");
        assert_eq!(canonical_identifier(ManagerName::Cargo, "Cargo_Edit"), "cargo-edit");
        assert_eq!(
            canonical_identifier(ManagerName::PowerShell, "Az.Accounts"),
            "az.accounts"
        );
        assert_eq!(canonical_identifier(ManagerName::Chocolatey, "Git"), "git");
        assert_eq!(canonical_identifier(ManagerName::Winget, "Git.Git"), "git.git");
        assert_eq!(canonical_identifier(ManagerName::Npm, "JSONStream"), "JSONStream");
    }

    #[test]
    fn winget_identifiers_ignore_case_for_both_decisions() {
        for decision in [Decision::Allow, Decision::Deny] {
            assert!(matches(ManagerName::Winget, "git.git", &exact(&["Git.Git"]), decision));
            assert!(matches(
                ManagerName::Winget,
                "microsoft.vscode",
                &patterns(&["Microsoft.*"]),
                decision
            ));
        }
    }

    #[test]
    fn exact_identifiers_use_canonical_form_for_both_decisions() {
        for decision in [Decision::Allow, Decision::Deny] {
            assert!(matches(
                ManagerName::PowerShell,
                "az.accounts",
                &exact(&["Az.Accounts"]),
                decision
            ));
            assert!(matches(ManagerName::Chocolatey, "GIT", &exact(&["git"]), decision));
            assert!(matches(
                ManagerName::Pip,
                "Python_Dateutil",
                &exact(&["python-dateutil"]),
                decision
            ));
            assert!(matches(
                ManagerName::Cargo,
                "cargo_edit",
                &exact(&["cargo-edit"]),
                decision
            ));
            assert!(!matches(
                ManagerName::Pip,
                "python-dateutils",
                &exact(&["python-dateutil"]),
                decision
            ));
        }
    }

    #[test]
    fn deny_identifiers_ignore_case_for_case_sensitive_managers() {
        for manager in [ManagerName::Npm, ManagerName::Bun] {
            assert!(matches(manager, "jsonstream", &exact(&["JSONStream"]), Decision::Deny));
            assert!(!matches(
                manager,
                "jsonstream",
                &exact(&["JSONStream"]),
                Decision::Allow
            ));
        }
    }

    #[test]
    fn patterns_use_canonical_form() {
        for decision in [Decision::Allow, Decision::Deny] {
            assert!(matches(
                ManagerName::Pip,
                "Django_REST.framework",
                &patterns(&["django-rest-*"]),
                decision
            ));
            assert!(matches(
                ManagerName::Cargo,
                "tokio_util",
                &patterns(&["tokio-*"]),
                decision
            ));
            assert!(matches(
                ManagerName::Winget,
                "Microsoft.VSCode",
                &patterns(&["Microsoft.*"]),
                decision
            ));
            assert!(matches(
                ManagerName::PowerShell,
                "az.accounts",
                &patterns(&["Az.*"]),
                decision
            ));
            assert!(!matches(ManagerName::Pip, "flask", &patterns(&["django-*"]), decision));
        }
    }

    #[test]
    fn deny_patterns_use_unicode_case_folding() {
        assert!(matches(
            ManagerName::PowerShell,
            "kmodule",
            &patterns(&["\u{212A}*"]),
            Decision::Deny
        ));
        assert!(!matches(
            ManagerName::PowerShell,
            "kmodule",
            &patterns(&["\u{212A}*"]),
            Decision::Allow
        ));
    }

    #[test]
    fn allow_patterns_preserve_case_for_case_sensitive_managers() {
        for manager in [ManagerName::Npm, ManagerName::Bun] {
            assert!(!matches(manager, "jsonstream", &patterns(&["JSON*"]), Decision::Allow));
            assert!(matches(manager, "jsonstream", &patterns(&["JSON*"]), Decision::Deny));
        }
    }

    #[test]
    fn deny_rules_match_names_embedded_in_decorated_identifiers() {
        let cases = [
            (ManagerName::Npm, "alias:@babel/core@7.0.0", "@babel/core"),
            (ManagerName::Npm, "alias@npm:react", "react"),
            (ManagerName::Npm, "owner/repo#v1", "owner/repo"),
            (ManagerName::Npm, "alias:owner/repo#semver:^1", "owner/repo"),
            (ManagerName::Bun, "react@18.0.0", "react"),
            (ManagerName::Vcpkg, "zlib:x64-windows", "zlib"),
            (ManagerName::Vcpkg, "curl[ssl,http2]:x64-windows", "curl"),
            (ManagerName::Scoop, "7zip@19.00", "7zip"),
            (ManagerName::Dotnet, "dotnetsay@2.1.0", "dotnetsay"),
        ];

        for (manager, value, denied) in cases {
            assert!(matches(manager, value, &exact(&[denied]), Decision::Deny), "{value}");
            assert!(matches(manager, value, &patterns(&[denied]), Decision::Deny), "{value}");
            assert!(!matches(manager, value, &exact(&[denied]), Decision::Allow), "{value}");
        }
    }

    #[test]
    fn embedded_names_keep_npm_scopes() {
        assert_eq!(embedded_package_names(ManagerName::Npm, "@scope/pkg"), ["@scope/pkg"]);
        assert!(!identifier_may_select_version("@scope/pkg"));
        assert!(identifier_may_select_version("@scope/pkg@1.0.0"));
        assert!(identifier_may_select_version("alias:react@18"));
        assert!(!identifier_may_select_version("alias:react"));
    }

    #[test]
    fn unknown_npm_and_bun_identities_match_every_deny_identifier_rule() {
        let unknown = [
            (ManagerName::Npm, "owner/repo"),
            (ManagerName::Npm, "owner/repo#v1"),
            (ManagerName::Npm, "git+https://github.com/owner/repo.git#v1"),
            (ManagerName::Bun, "git+https://github.com/owner/repo.git#v1"),
            (ManagerName::Bun, "github:owner/repo"),
            (ManagerName::Bun, "file:../local"),
            (ManagerName::Bun, "alias@github:owner/repo"),
            (ManagerName::Npm, "."),
            (ManagerName::Npm, ".."),
            (ManagerName::Bun, ".."),
            (ManagerName::Npm, "_private"),
            (ManagerName::Npm, "@/pkg"),
            (ManagerName::Npm, "@scope/.hidden"),
        ];
        for (manager, value) in unknown {
            assert!(has_unknown_identity(manager, value), "{value}");
            assert!(matches(manager, value, &exact(&["lodash"]), Decision::Deny), "{value}");
            assert!(
                !matches(manager, value, &exact(&["lodash"]), Decision::Allow),
                "{value}"
            );
        }

        let known = [
            (ManagerName::Npm, "lodash"),
            (ManagerName::Npm, "@scope/pkg"),
            (ManagerName::Npm, "alias:@babel/core@7.0.0"),
            (ManagerName::Bun, "npm:react"),
            (ManagerName::Bun, "alias@npm:react@18.0.0"),
            (ManagerName::Winget, "Owner/Repo#1"),
        ];
        for (manager, value) in known {
            assert!(!has_unknown_identity(manager, value), "{value}");
        }
        assert!(!matches(
            ManagerName::Bun,
            "npm:react",
            &exact(&["lodash"]),
            Decision::Deny
        ));
    }

    #[test]
    fn qualifiers_are_not_package_names() {
        assert_eq!(embedded_package_names(ManagerName::Bun, "npm:react"), ["react"]);
        assert_eq!(
            embedded_package_names(ManagerName::Bun, "alias@npm:react@18.0.0"),
            ["alias", "react"]
        );
        assert_eq!(
            embedded_package_names(ManagerName::Bun, "npm@npm:react"),
            ["npm", "react"]
        );
        for shortcut in ["gitlab", "bitbucket", "gist", "sourcehut", "github", "file"] {
            let value = format!("{shortcut}:owner/repo");
            assert_eq!(embedded_package_names(ManagerName::Bun, &value), ["owner/repo"]);
            let value = format!("{shortcut}:owner/repo#v1.2.3");
            assert_eq!(embedded_package_names(ManagerName::Bun, &value), ["owner/repo"]);
            assert!(identifier_may_select_version(&value));
        }
        assert!(!matches(
            ManagerName::Bun,
            "npm:react",
            &exact(&["npm"]),
            Decision::Deny
        ));
        assert!(matches(
            ManagerName::Bun,
            "npm:react",
            &exact(&["react"]),
            Decision::Deny
        ));
        assert_eq!(
            embedded_package_names(ManagerName::Vcpkg, "curl[ssl]:x64-windows"),
            ["curl"]
        );
        assert!(!matches(
            ManagerName::Vcpkg,
            "zlib:x64-windows",
            &exact(&["x64-windows"]),
            Decision::Deny
        ));
        assert!(!matches(
            ManagerName::Scoop,
            "app:other",
            &exact(&["other"]),
            Decision::Deny
        ));
    }

    #[test]
    fn absent_condition_matches_any_identifier() {
        assert!(package_identifiers_match(
            ManagerName::Winget,
            "Any.Package",
            None,
            Decision::Deny
        ));
    }
}
