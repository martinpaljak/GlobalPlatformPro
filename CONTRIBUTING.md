# Support and Issues
  * **IMPORTANT**: If you can not access your card due to invalid keying, please be sure that you can contribute very detailed information about your card and keying data (and send a reference card, if needed) or pinpoint the actual faulty functions in GPPro, before opening a ticket. **This is just a tool, you need to do your own lockpicking and are responsible if the tool gets stuck in the lock!**
  * Please only file a ticket if you think that **there is a bug** in GlobalPlatformPro or if **something can be improved** in GlobalPlatformPro.
  * **NO** generic questions about java/linux/smartcards/7816/windows/globalplatform/world politics/random APDU-s. They **shall be closed as invalid**. You may try your luck on stackoverflow.com or do your googling and homework.
  * Questions solely about jcshell/gpshell/gpj/gemexpresso/something else **shall be ignored**.
     * If you DO have a question about how to use GPPro, start the ticket with `Question: `
     * Comparative APDU traces from other software might be handy in debugging if specifications remain unclear and are OK
  * Re-run your failing command with `-d -v -i` switches and send the output with information about your card and applet/CAP
  * **Only plaintext** logs. **NO** screenshots, pictures, word documents.
  * If unsure, first read about [asking questions](http://www.catb.org/esr/faqs/smart-questions.html)
  * I shall not guide your EMV emulation-cloning adventures, even for some bitcoin(s).
  * If you are asking for help in a legitimate commercial (not open source) endeavour, send an e-mail to martin@martinpaljak.net

# Contributing to GlobalPlatformPro
 * Use the software!
 * Send card information
 * Send debug logs (with `--debug` and `--verbose`)
 * All patches must be with MIT license.
   * Check easy issues: https://github.com/martinpaljak/GlobalPlatformPro/contribute 

### Debian/Ubuntu
 * Install dependencies: `apt-get install --no-install-recommends libccid openjdk-11-jdk git`

### Fedora/CentOS
 * Install dependencies: `yum install pcsc-lite-ccid java-11-openjdk-devel git`
 * Start pcscd service: `service pcscd start`

### FreeBSD
 * Install dependencies: `pkg install devel/libccid java/openjdk11 devel/git`
