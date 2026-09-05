# Agent Instructions

- Use `./mvnw` (Maven wrapper), never `mvn`
- When compiling a single module with `-pl`, always use `-am` (also-make) to build its dependencies: `./mvnw compile -pl tool -am`
- Run `./mvnw verify` as the final check — must be clean before committing
- Compiler uses `-Werror -Xlint:all` — all warnings are errors

## Dependency Updates

Run `make versions` to check for newer versions of dependencies, plugins, and extensions. The output is unfiltered — review it fully and apply updates to `pom.xml` as appropriate.

## Code Quality Workflow

Before committing, run these in order:

1. `./mvnw -Pcheck -Dmaven.javadoc.skip=true -Dmaven.test.skip=true compile spotbugs:check` — SpotBugs static analysis, excludes in `spotbugs.xml`
2. `./mvnw rewrite:run spotless:apply` — OpenRewrite auto-fixes and code formatting
3. `./mvnw verify` — final build + tests, must be clean

OpenRewrite applies automatic fixes (var inference, String.formatted, finality, etc.). Spotless applies the Eclipse formatter. Both modify source files in place — review the changes before committing.

Configuration: `eclipse-formatter.xml` in the project root. `module-info.java` files are excluded from formatting.

Use `@formatter:off` / `@formatter:on` to protect sections from automatic formatting.

## Wiki

This project has a GitHub wiki. It should ALWAYS be cloned into the `./wiki` directory before starting work:

    git clone git@github.com:martinpaljak/GlobalPlatformPro.wiki.git wiki

When making changes to the codebase, verify that the wiki does not contradict the source code — update wiki pages as needed to keep documentation consistent with actual behavior.
