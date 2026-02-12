# Agent Instructions

- Use `./mvnw` (Maven wrapper), never `mvn`
- Use `./mvnw compile` or module-specific builds during development
- Run `./mvnw verify` as the final check — must be clean before committing
- Java 17+ required
- Compiler uses `-Werror -Xlint:all` — all warnings are errors

## Dependency Updates

Run `make versions` to check for newer versions of dependencies, plugins, and extensions. The output is unfiltered — review it fully and apply updates to `pom.xml` as appropriate.

## Code Quality Workflow

Before committing, run these in order:

1. `./mvnw -Perrorprone -Dmaven.javadoc.skip=true -Dmaven.test.skip=true compile spotbugs:check` — Error Prone and SpotBugs static analysis
2. `./mvnw rewrite:run spotless:apply` — OpenRewrite auto-fixes and code formatting
3. `./mvnw verify` — final build + tests, must be clean

OpenRewrite applies automatic fixes (var inference, String.formatted, finality, etc.). Spotless applies the Eclipse formatter. Both modify source files in place — review the changes before committing.

Configuration: `eclipse-formatter.xml` in the project root. `module-info.java` files are excluded from formatting.

Use `@formatter:off` / `@formatter:on` to protect sections from automatic formatting.

## Project Structure

Multi-module Maven project. All source under `pro.javacard.*` packages.

| Module     | Package              | Description                              |
|------------|----------------------|------------------------------------------|
| `library`  | `pro.javacard.gp`   | Core library — GP card sessions, crypto, commands, registry |
| `tool`     | `pro.javacard.gptool`| CLI tool (`GPTool`) wrapping the library |
| `tlv`      | `pro.javacard.tlv`  | TLV (Tag-Length-Value) parsing utilities  |
| `pace`     | `pro.javacard.pace` | PACE protocol implementation             |
| `prefs`    | `pro.javacard.prefs`| Preferences/config handling              |

Tests live in each module's `src/test/` (except `pace`).

## Wiki

This project has a GitHub wiki. It should ALWAYS be cloned into the `./wiki` directory before starting work:

    git clone git@github.com:martinpaljak/GlobalPlatformPro.wiki.git wiki

When making changes to the codebase, verify that the wiki does not contradict the source code — update wiki pages as needed to keep documentation consistent with actual behavior.

## Specifications

Relevant specifications are available as text files in `docs/`. Consult them when working on protocol-level code or command structures.
