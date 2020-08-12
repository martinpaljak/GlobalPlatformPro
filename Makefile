MVN_OPTS = -Dmaven.javadoc.skip=true -Dmaven.test.skip=true -Dspotbugs.skip=true

SOURCES = $(shell find tool library -name '*.java' -o -name 'pom.xml')
default: install

tool/target/gp.jar: $(SOURCES)
	./mvnw $(MVN_OPTS) package

dep: $(SOURCES)
	./mvnw $(MVN_OPTS) install

install: ~/.apdu4j/apps/gp.jar

~/.apdu4j/apps/gp.jar: tool/target/gp.jar
	mkdir -p ~/.apdu4j/apps
	cp tool/target/gp.jar ~/.apdu4j/apps/gp.jar

clean:
	./mvnw clean

test:
	./mvnw verify
