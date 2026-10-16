# Pitfalls seen in real intent drafts

Each entry is a mistake that reached review, the correction, and the general rule it taught.
Run a draft through this list before handing it back.

## Content in the wrong artifact

- **Restating the spec.**
  A rationale intent opened with "this file records the decisions it must preserve" and then reproduced the token format, an operations table, and conventions.
  The maintainer made `CONTRACT.md` self-contained and rewrote the intent as rationale: "it repeats contract details only when needed to explain a design choice".
  Rule: exact field lists, limits, timers, paths, statuses, and check order are specified and tested in the contract; none is a decision worth preserving on its own.
- **Process text in intent.**
  Stages, decision identifiers, agent roles, PR sequencing, and test-writing workflow appeared in drafts.
  The maintainer: "Just the spec, and implementation decisions, nothing on the agent operational side."
  Rule: if it describes how an agent navigates, modifies, validates, or reasons about the repository, it belongs in `AGENTS.md` or the plan.
- **Restating what CI enforces.**
  "It passes the full conformance suite" in every backend intent.
  Rule: a clause that a check already enforces is noise; a clause that costs a CI round-trip or an incident to discover is the point.
- **Inventories that rot.**
  A generated scope list was stale, an example issue number was wrong, and a crate list was stale in both directions.
  Rule: prefer rules over lists; when a list is needed, point at the authoritative one.

## Claims that were false somewhere

- **"Every library imports SPKI."**
  ring has no SPKI parser; the intent changed to "the contents of the SPKI `subjectPublicKey`".
  Rule: verify each universal claim against pinned sources before writing it.
- **"Fill-in providers implement what no library offers."**
  aws-lc offers the KDFs; it became "what some backend's library lacks".
- **"The agent never sends its certificate to authenticate."**
  A planned mTLS path legitimately sends it to another component; it became "to the authority".
  Rule: scope every absolute to the boundary it protects.
- **"Authorities differ only by base URL."**
  They also expose product-specific management APIs; it became "use different base URLs and may provide product-specific configuration and management APIs".
- **"The bundle's `fips()` is false."**
  A bundle containing only an aws-lc FIPS build falsifies it; it became "a non-FIPS convenience that claims nothing".
  Rule: test the sentence against every configuration the build system allows.
- **Library-specific behaviour presented as a general rule.**
  "p = q" appeared in an inconsistent-key rule only because one RSA crate behaves that way; it became "components that are not a consistent RSA private key for (n, e)".
  Rule: leave out behaviour and numbers tied to one implementation.
- **A rationale that measurement contradicted.**
  A capacity-limit rationale cited stack growth during decoding; measurement showed key construction grew the stack.
  Rule: a reason must be as true as the rule it explains.

## Absolutes that agents read literally

- "A hand-written input never expects success" broke when boundary controls needed acceptance.
  It became three lines naming the allowed exceptions.
- "`Unsupported` is allowed above the must-support set" missed inputs below it (1-byte RC4 keys); it became "outside".
  Rule: expect literal readings, name the exceptions, and run a reviewer that hunts for contradictions.

## Structure and maintenance

- **Deleting a rule but leaving references.**
  After "thin adapter" was dropped, "the thin-adapter rule applies to backends only" pointed at nothing.
  Rule: grep for every reference by name when removing a rule.
- **Links broke on rename.**
  Renaming `contract.intent.md` to `INTENT.md` broke four links; stable `<a id="...">` anchors fixed it.
- **Wrong placement.**
  A shared contract intent sat under one crate; it moved to `docs/<feature>/` because several components share it, and each crate intent links to it because intent applies by directory.
- **A tooling gotcha.**
  An intent-only directory for a crate that did not exist yet broke `members = ["crates/*"]` and needed a temporary `exclude`.
- **Repetition across sibling files.**
  "A backend is a thin adapter" in every backend intent drew "does that belong to this crate?" and "how useful is that invariant?".
  Rule: state once, in the most general file, and refer to it.
- **A bare rule without its reason.**
  "`fips()` always returns `false`" drew "explain why".

## Timing and process

- **Drafting before the design settled.**
  Packaging changed three times, and each time the intents, the contract, and every file naming the crate changed.
  Drafts written during a design conversation needed sixteen corrections a day later.
  Rule: write intent after decisions settle; re-check every draft against the decision log before handing it over; ship intent edits in a small separate PR ahead of the code that depends on them.
- **Drift between the approved text and the files.**
  One approved edit never reached the source bundle, and a superseded sentence survived in a section file.
  Rule: keep one source, log the exact approved text, and verify byte for byte at each copy.
- **Silently filled gaps.**
  Encodings, a thumbprint definition, and a grace-window formula were defined by the drafter and never discussed.
  Rule: track provenance and list filled gaps for the human.
- **History instead of rationale.**
  "Was changed because…" in committed text.
  Rule: state the reason as a reason; keep the record of decisions outside the repository.

## What maintainers push back on in review

Quotes from intent-file reviews in Devolutions repositories, one per pattern.

- **Plan or ticket tense.**
  "The intent file should be normative. 'We would like to...' only fits behavior we intentionally haven't implemented yet, and this behavior is already implemented." ([devolutions-gateway #1942](https://github.com/Devolutions/devolutions-gateway/pull/1942#discussion_r4157014381))
  "This sounds like a ticket body. Write in present tense, in a normative way, describing how things are expected to be at any point in time." ([devolutions-gateway #2003](https://github.com/Devolutions/devolutions-gateway/pull/2003#discussion_r4129433952))
  Future direction is allowed as a short, labelled "Later, X could …" note.
- **Not true of the implementation.**
  "'Each client begins at its own live edge' isn't always true with the current implementation. Can we state the actual rule here?" ([#1942](https://github.com/Devolutions/devolutions-gateway/pull/1942#discussion_r4198134333))
  "Try to run an audit to compare the intent files against the implementation." ([#1942](https://github.com/Devolutions/devolutions-gateway/pull/1942#pullrequestreview-5381278219))
- **Too absolute: narrow or drop.**
  "Either drop the backward-compatibility claim or narrow it to 'Clients receive no `SegmentStarted` message before the first segment'." ([#1942](https://github.com/Devolutions/devolutions-gateway/pull/1942#discussion_r4157014381))
  "It's 2026.3.0, specifically; because 2026.3.1 is also 2026.3 and it will have a different format." ([#2039](https://github.com/Devolutions/devolutions-gateway/pull/2039#discussion_r4221382200))
- **Enforced but unwritten.**
  "The actual wire contract isn't written down. Suggest rewriting it as: inputs, normalized output guarantees, and an exact Start/Pull/response transcript." ([#1942](https://github.com/Devolutions/devolutions-gateway/pull/1942#discussion_r4156764692))
- **Invariants come out of review and go into the intent.**
  "`gateway-db` must never depend on crates that implement feature behavior. Adapters may depend on `gateway-db`, but never the other way around. Please add this to the invariants in `crates/gateway-db/INTENT.md`." ([#2039](https://github.com/Devolutions/devolutions-gateway/pull/2039#pullrequestreview-5457434157))
  "Write some human-vetted invariants about the concrete invariants and intentions you encoded when authoring this PR." ([#1946](https://github.com/Devolutions/devolutions-gateway/pull/1946#pullrequestreview-5018598898))
- **Non-goals and tradeoffs with their why.**
  "It's good to explain we don't want to turn that into a generic LLM client. Also, I would document that a vendored implementation is intentional to reduce dependencies." ([#2005](https://github.com/Devolutions/devolutions-gateway/pull/2005#discussion_r4156224738))
- **Not a README, not the path.**
  "This is verbatim the same as what is written in the README.md. INTENT.md is not intended to be the same as README.md." ([IronVNC #1542](https://github.com/Devolutions/IronVNC/pull/1542#discussion_r4013943689))
  "I would remove this, as it's part of the file name / convention." ([#1946](https://github.com/Devolutions/devolutions-gateway/pull/1946#discussion_r3898220402))
- **Files must agree.**
  "The two intent files now disagree. Both are human-owned, so the wording needs the maintainer's approval." ([picky-rs #572](https://github.com/Devolutions/picky-rs/pull/572#discussion_r4282323307))
- **About the software, not about agents.**
  A testsuite intent line was reworded "so it no longer refers to agents". ([picky-rs #556](https://github.com/Devolutions/picky-rs/pull/556#discussion_r4238310499))
- **Form.**
  One sentence per line, typos listed exhaustively, trailing newline, no heading that repeats the folder name. ([#1942](https://github.com/Devolutions/devolutions-gateway/pull/1942#discussion_r4156764692), [IronVNC #1544](https://github.com/Devolutions/IronVNC/pull/1544#discussion_r4024059256))
