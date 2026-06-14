# Changelog

Notable changes per release. Versions follow CalVer (`vYY.MM.DD`).
Downloads and full notes: https://github.com/martinpaljak/GlobalPlatformPro/releases

## v26.06.04 (2026-06-04)

### nextgen
 - ARA-M (Access Rule Application) access control: list, add and delete rules, ARA-C targeting and `--ara-nfc` rules
 - CRS recipes split into their own cookbook; added the `--simulator` flag
 - `--crs-list` returns all data, with fixed `88` decode and registry-update parameters

### Library and tool
 - PACE validates the key returned by the card
 - Dropped the `APDUBIBO` interface in favour of the current apdu4j Readers API
 - Builds on Java 25

### Internals
 - New path-addressed, pure-functional TLV editing API (TPath/TLVs), adopted across all modules
 - apdu4j 26.06.04, with remote adapters moved out of jcardengine into apdu4j
 - REUSE 3.3 inline SPDX headers, dependency and Maven plugin updates

Older releases are listed under [git tags](https://github.com/martinpaljak/GlobalPlatformPro/tags).
