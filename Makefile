 # same as Github
export TZ = UTC
export JAVA_HOME ?= /Library/Java/JavaVirtualMachines/zulu-21.jdk/Contents/Home

MVN_OPTS = -Dmaven.javadoc.skip=true -Dmaven.test.skip=true -Dspotbugs.skip=true
VERSIONS = org.codehaus.mojo:versions-maven-plugin:2.21.0
VERSION_RULES = -Dmaven.version.rules=file://$(shell pwd)/version-rules.xml

SOURCES = $(shell find tlv library pace nextgen tool -name '*.java' -o -name 'pom.xml') pom.xml Makefile
XMLS = $(shell find . -name '*.xml' -not -path '*/target/*')

default: today tool/target/gp.jar

tool/target/gp.jar: $(SOURCES)
	./mvnw $(MVN_OPTS) package

dep: $(SOURCES)
	./mvnw $(MVN_OPTS) install

# OpenRewrite edits every module during the last one, so it must finish before the formatter starts
source:
	./mvnw -P fixup process-test-classes
	./mvnw spotless:apply

fast:
	./mvnw -T1C install -Dmaven.test.skip=true -Dspotbugs.skip=true

ci:
	CI=true ./mvnw -U -P exe

versions:
	./mvnw -B --no-transfer-progress $(VERSIONS):display-parent-updates $(VERSIONS):display-dependency-updates $(VERSIONS):display-plugin-updates $(VERSIONS):display-extension-updates $(VERSION_RULES)

xml:
	@command -v xmllint >/dev/null 2>&1 || { echo "xmllint not found (install libxml2-utils)"; exit 1; }
	@for f in $(XMLS); do XMLLINT_INDENT='    ' xmllint --format "$$f" > "$$f.tmp" && mv "$$f.tmp" "$$f"; done

today:
	# for a dirty tree, set the date to today
	test -z "$(shell git status --porcelain)" || ./mvnw $(VERSIONS):set -DnewVersion=$(shell date +%y.%m.%d)-SNAPSHOT -DgenerateBackupPoms=false

reuse:
	reuse --no-multiprocessing lint
