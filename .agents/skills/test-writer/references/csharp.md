# C# forms

The repository's C# tests are xUnit v2; each rule in `SKILL.md` takes these forms there.

Properties use CsCheck: compose `Gen<T>` with LINQ and `Sample` it; keep each type's generator in one static class of the test project so it is written once, as a crate keeps its strategies.
A failing `Sample` prints a seed; replay it with `seed:` or the `CsCheck_Seed` environment variable, and pin a regression by keeping the shrunk value as an `[InlineData]` row rather than the seed, since a generator change moves the seed's meaning.
No fuzz harness exists for the repository's C#, so a parser of untrusted input gets a CsCheck property over malformed inputs, and the report says it is not fuzzed.

No snapshot library is in use; write the expected value inline and, past a screen, in a sibling file copied into the test output.
Nothing rewrites a stale value, so each is edited by hand after reading it.

Cases are `[Theory]` with `[InlineData]` rows for literal data, whose display name carries the arguments, so a failure names the row as `#[case::name]` does.
Other data goes through `[MemberData(nameof(<Member>))]` with a string key per row, because rows whose arguments xUnit cannot serialize share one test case, which no filter or kill matrix can tell apart.
A cross product is a `[MemberData]` member that yields it, so the `#[values]` rule applies to that member.
A regression test is a `[Fact]` named for its issue.
