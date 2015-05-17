# Contributing to GlobalPlatformPro
 * Use the software!
 * Send card information
 * Send debug logs
 * All patches must be with MIT license.

## Building the software
Simple `ant` will produce working results if you have the dependencies.

### Debian/Ubuntu
 * Install dependencies: `apt-get install --no-install-recommends libccid openjdk-7-jdk git ant`

### Fedora/CentOS
 * Install dependencies: `yum install pcsc-lite-ccid java-1.8.0-openjdk git ant`
 * Start pcscd service: `service pcscd start`

### FreeBSD
 * Install dependencies: `pkg install devel/libccid java/openjdk7 devel/apache-ant devel/git`

## Note about Oracle JDK
 * Compiled against Java 1.7+ but only tested with latest Java 1.8
  * 1.7 is at EOL: http://www.oracle.com/us/technologies/java/eol-135779.html   
 * Requires "Unlimited Strength Jurisdiction Policy Files"
  * Download for Java 1.7: http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
  * Download for Java 1.8: http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

## Building Windows executable
 * Download [launch4j](http://launch4j.sourceforge.net/) and extract a version matching your host platform into `ext/launch4j`
 * Run `ant windist`
