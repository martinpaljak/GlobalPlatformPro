export TZ = UTC # same as Github
export JAVA_HOME ?= /Library/Java/JavaVirtualMachines/zulu-11.jdk/Contents/Home

MVN_OPTS = -Dmaven.javadoc.skip=true -Dmaven.test.skip=true -Dspotbugs.skip=true

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

clean:
	./mvnw clean

test:
	./mvnw verify

fast:
	./mvnw -T1C install -Dmaven.test.skip=true -Dspotbugs.skip=true

today:
	# for a dirty tree, set the date to today
	test -z "$(shell git status --porcelain)" || ./mvnw versions:set -DnewVersion=$(shell date +%y.%m.%d)-SNAPSHOT -DgenerateBackupPoms=false
