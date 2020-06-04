MVN_OPTS = -Dmaven.javadoc.skip=true -Dmaven.test.skip=true

default: install

tool/target/gp.jar: $(shell find tool library -name '*.java')
	./mvnw $(MVN_OPTS) package

dep:
	./mvnw $(MVN_OPTS) install

install: ~/.apdu4j/plugins/gp.jar

~/.apdu4j/plugins/gp.jar: tool/target/gp.jar
	mkdir -p ~/.apdu4j/plugins
	cp tool/target/gp.jar ~/.apdu4j/plugins/gp.jar

clean:
	./mvnw clean
