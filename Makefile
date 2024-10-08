export TZ = UTC # same as Github
export JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-11.jdk/Contents/Home

MVN_OPTS = -Dmaven.javadoc.skip=true -Dmaven.test.skip=true -Dspotbugs.skip=true

SOURCES = $(shell find pace tool library -name '*.java' -o -name 'pom.xml') pom.xml Makefile

default: tool/target/gp.jar

tool/target/gp.jar: $(SOURCES)
	./mvnw $(MVN_OPTS) package

dep: $(SOURCES)
	./mvnw $(MVN_OPTS) install

clean:
	./mvnw clean

test:
	./mvnw verify

fast:
	./mvnw -T1C install -Dmaven.test.skip=true -Dspotbugs.skip=true
