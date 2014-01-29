# GlobalPlatform from [OpenKMS](http://openkms.org)

Load and manage applets on compatible JavaCards from command line or from your Java project with a [DWIM](http://en.wikipedia.org/wiki/DWIM) approach.

Provides a **high level** and **easy to use** interface that most of the time **JustWorks<sup>(TM)</sup>** yet is as **flexible** as GPShell.

### Get it now!
 * Download latest pre-built JAR from [release area](https://github.com/martinpaljak/GlobalPlatform/releases)
 * Or fetch from github and build it yourself, it is easy:

        git clone https://github.com/martinpaljak/GlobalPlatform
        cd GlobalPlatform
        ant

### Usage

*Beware: until v1.0 is released, both command line and Java API are subject to change without notice.*

Command line samples assume default test keys of ```40..4F```. If you need custom keys, specify them with any or all of the following options: ```-keyid``` ```-keyver``` and ```-enc``` ```-mac``` ```-kek``` (you need to know the details or ask your card provider). Some cards require key diversification with ```-emv``` or ```-visa2``` (you should be notified if that's the case).

 * Show some basic information about a card (failsafe):

        java -jar gp.jar -info

 * List applets (this and following commands can block your card):

        java -jar gp.jar -list

 * Delete current default applet:

        java -jar gp.jar -delete -default

 * Install applet.cap as default applet (with AID information from the CAP):

        java -jar gp.jar -load applet.cap -install -default
 
 * Show APDU-s sent to the card:
   
   add ```-debug``` to your command

 * Don't use MAC on commands (plain GlobalPlatform commands):

   add ```-mode clr``` to your command (not supported on all cards)

##### Usage from Java
 * Check the (currently in very bad shape) [javadoc](http://martinpaljak.github.io/GlobalPlatform/)
 * Or the [command line utility source code](https://github.com/martinpaljak/GlobalPlatform/blob/master/src/openkms/gpj/GPJTool.java)

### Contact 

 * martin@martinpaljak.net
 * .. or file an issue on Github. Better yet - a pull request!
 * For general conversation: [google forum](https://groups.google.com/forum/#!forum/openkms)

### History

The ancestor of this code is GPJ (Global Platform for SmartCardIO)
available from http://gpj.sourceforge.net.

### License

 * [LGPL 3.0](http://www.gnu.org/licenses/lgpl-3.0.html)

### Credits (from GPJ):
 *  Wojciech Mostowski <woj@cs.ru.nl>,
 *  Francois Kooman <F.Kooman@student.science.ru.nl>
 *  Martijn Oostdijk <martijn.oostdijk@gmail.com>
 *  Martin Paljak <martin@martinpaljak.net>
 *  Hendrik Tews
 *  Dusan Kovacevic

### Similar projects
 * gpj (the grandparent) - http://gpj.sf.net (LGPL)
   * written in Java 
   * not maintained
   * harder to use from the command line
 * GPShell + globalplatform library - http://sourceforge.net/projects/globalplatform/ (LGPL)
   * written in C
   * several components need to be installed and compiled
   * requires more complex "script files" and does not provide a command line utility
   * often referred to as the de facto open source GlobalPlatform implementation.
 * jcManager - http://www.brokenmill.com/2010/03/java-secure-card-manager/ (LGPL)
   * written in Java  
   * has a GUI
   * old and not maintained
 * gpjNG - https://github.com/SimplyTapp/gpjNG (LGPL)
   * fork of gpj with minor additions, mostly a "script mode" that makes it similar to GPShell
 * JCOP tools, RADIII, JCardManager4 etc
   * not publicly available open source projects and thus not suitable for this comparision

## About OpenKMS
The promise of OpenKMS is similar to OpenSSL: 
    
    Why buy a smart card software kit as a black box when you can get an open one for free?
<sub>(with the difference that OpenKMS thrives for a secure, easily usable and pleasantly readable codebase). And yes, you have probably already sold your soul to the devil...</sub>

----
OpenKMS - open source key management - [openkms.org](http://openkms.org)
