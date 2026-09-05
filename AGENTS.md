# Agent Instructions

- Use `./mvnw` (Maven wrapper), never `mvn`
- When compiling a single module with `-pl`, always use `-am` (also-make) to build its dependencies: `./mvnw compile -pl tool -am`
- Run `./mvnw verify` as the final check: must be clean before committing
- Compiler uses `-Werror -Xlint:all`: all warnings are errors

## Dependency Updates

Run `make versions` to check for newer versions of dependencies, plugins, and extensions. The output is unfiltered: review it fully and apply updates to `pom.xml`.

## Code Quality Workflow

Before committing, run these in order:

1. `make source`: always modifies. OpenRewrite auto-fixes, then the Eclipse formatter, as two Maven rounds
2. `CI=true ./mvnw clean verify`: never modifies. Build, tests, SpotBugs and `spotless:check`, must be clean

OpenRewrite (var inference, String.formatted, finality) runs from `make source` only. It edits every module during the last one, so the formatter has to be a second Maven round. Both rounds rewrite source in place: review the changes before committing.

The `check` profile activates on `env.CI=true` with JDK 21 or newer, so `-Pcheck` is never needed; `CI=true` alone brings in SpotBugs (excludes in `spotbugs.xml`) and `spotless:check`. Fix formatting failures with `make source`, not by hand.

Configuration: `eclipse-formatter.xml` in the project root. Spotless skips `module-info.java`.

Use `@formatter:off` / `@formatter:on` to protect sections from automatic formatting.

## Wiki

This project has a GitHub wiki. ALWAYS clone it into `./wiki` before starting work:

    git clone git@github.com:martinpaljak/GlobalPlatformPro.wiki.git wiki

When changing the codebase, verify that the wiki does not contradict the source code. Update wiki pages to keep documentation consistent with actual behavior.
