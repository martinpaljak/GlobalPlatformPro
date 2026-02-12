export TZ = UTC # same as Github
export JAVA_HOME ?= /Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home

MVN_OPTS = -Dmaven.javadoc.skip=true -Dmaven.test.skip=true -Dspotbugs.skip=true
VERSIONS = org.codehaus.mojo:versions-maven-plugin:2.21.0
VERSION_RULES = -Dmaven.version.rules=file://$(shell pwd)/version-rules.xml

SOURCES = $(shell find pace tool library -name '*.java' -o -name 'pom.xml') pom.xml Makefile

default: today tool/target/gp.jar

tool/target/gp.jar: $(SOURCES)
	./mvnw $(MVN_OPTS) package

srcbuild:
	# override the version, which would be "unsupported" without a git checkout
ifdef GPPRO_VERSION
	mkdir -p ./library/target/classes/pro/javacard/gp
	echo "git.commit.id.describe=$(GPPRO_VERSION)" > ./library/target/classes/pro/javacard/gp/git.properties
endif
	./mvnw $(MVN_OPTS) -Dmaven.gitcommitid.skip=true package

dep: $(SOURCES)
	./mvnw $(MVN_OPTS) install

source:
	./mvnw rewrite:run spotless:apply

clean:
	./mvnw clean

test:
	./mvnw verify

fast:
	./mvnw -T1C install -Dmaven.test.skip=true -Dspotbugs.skip=true

check:
	./mvnw -Perrorprone -Dmaven.javadoc.skip=true -Dmaven.test.skip=true compile spotbugs:check

versions:
	./mvnw -B --no-transfer-progress $(VERSIONS):display-parent-updates $(VERSIONS):display-dependency-updates $(VERSIONS):display-plugin-updates $(VERSIONS):display-extension-updates $(VERSION_RULES)

today:
	# for a dirty tree, set the date to today
	test -z "$(shell git status --porcelain)" || ./mvnw $(VERSIONS):set -DnewVersion=$(shell date +%y.%m.%d)-SNAPSHOT -DgenerateBackupPoms=false
