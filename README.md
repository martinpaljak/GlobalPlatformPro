# GlobalPlatformPro &nbsp; [![Build Status](https://travis-ci.org/martinpaljak/GlobalPlatformPro.svg?branch=master)](https://travis-ci.org/martinpaljak/GlobalPlatformPro) [![Coverity status](https://scan.coverity.com/projects/4020/badge.svg?flat=1)](https://scan.coverity.com/projects/4020/) [![Latest release](https://img.shields.io/github/release/martinpaljak/GlobalPlatformPro.svg)](https://github.com/martinpaljak/GlobalPlatformPro/releases/latest)
*&nbsp;&nbsp;from [javacard.pro](http://javacard.pro)*

Load and manage applets on compatible JavaCards from command line or from your Java project with a [Do What I Mean](http://en.wikipedia.org/wiki/DWIM) approach ([testimonials](./docs/Testimonials.md)).

> Provides an **easy to use** and **high level** interface that most of the time **JustWorks<sup>(TM)</sup>**, is **flexible** and **[100% open source](#license)**!

Building JavaCard applets is equally pleasing with [ant-javacard](https://github.com/martinpaljak/ant-javacard)
#### Jump to ...
* [Download](#get-it-now)
* [Usage](#usage)
* [Supported cards](#supported-cards)
* [Contact & support](#contact)
* [Similar projects](#similar-projects)
* [About & legal](#about)


### Get it now!
* Download latest pre-built .JAR or .EXE from [release area](https://github.com/martinpaljak/GlobalPlatformPro/releases)
* Or build it yourself (see [CONTRIBUTING](./CONTRIBUTING.md) for tips), it is really easy:

```shell
git clone https://github.com/martinpaljak/GlobalPlatformPro
cd GlobalPlatformPro
ant
```

## NEWS
 * SCP03 support in [latest version](https://github.com/martinpaljak/GlobalPlatformPro/releases)
 * Tentative [milestones](https://github.com/martinpaljak/GlobalPlatformPro/milestones)
 * [JavaCard Buyer's Guide of 2016](https://github.com/martinpaljak/GlobalPlatformPro/tree/master/docs/JavaCardBuyersGuide)

### Usage

*Beware: [until v0.5 is released](https://github.com/martinpaljak/GlobalPlatformPro/milestones), both command line and Java API are subject to change without notice. Check back often.*

#### Warning about correct keying

Command line samples assume default test keys of `40..4F`. If you need a custom key, specify it with `-key` (you can give separate keyset components with `-key-mac`, `-key-enc` and `-key-kek`. You need to know the details or ask your card provider. Some cards require key diversification with `-emv` or `-visa2` (ask your vendor if unsure). A Key Check Value can be given with `-kcv` option.

#### Generic information

 * Show some basic information about a card (failsafe):

        java -jar gp.jar -info
        
   * On Windows just replace `java -jar gp.jar` with `gp.exe` like this:

            gp.exe -info

   * On Linux it is easier to add an alias to the shell like this:

            alias gp="java -jar $PWD/gp.jar"
            # Now you can avoid typing `java -jar` and `gp` works from any folder
            gp -h

#### List / install / delete applets
> Please consult the help output for options that are not described here

 * List applets (this and following commands open the secure channel and thus can brick your card with wrong keys!):

        gp -list # or gp -l

   How to interpret the output:
    * All AID-s of on-card objects are listed, starting with Issuer Security Domain (`ISD`)
    * Object's type, lifecycle state and privileges are listed below the `AID` line
    * Applications have type `App` and a state (like `SELECTABLE`) and privileges (like `Default selected`)
    * Executable Modules (type `ExM`, representing Java packages) are listed together with applets in them (which can be initiated with `--create`)
    * Security Domains have type `SeD`

 * Delete current default applet's package and all instances:

        gp -delete -default

 * Delete package ```D27600012401``` and all applets from it:

        gp -delete D27600012401

 * Install `applet.cap` as default applet (with AID information from the CAP):

        gp -install applet.cap -default

 * Install `applet.cap` (with AID information from the CAP):

        gp -install applet.cap

 * Unistall `applet.cap` (with AID information from the CAP):

        gp -uninstall applet.cap

 * Force installation of `applet.cap`, deleting anything that's necessary, with AID information from the CAP:

        gp -f -install applet.cap

 * Create new instance of applet `D2760001240102000000000000000000` from package `D27600012401` with AID `D2760001240102000000000272950000`:

        gp -package D27600012401 -applet D2760001240102000000000000000000 -create D2760001240102000000000272950000

 * Same as previous, but takes the package/applet AID-s from CAP file and makes the new instance default selected:

        gp -cap OpenPGPApplet.cap -create D2760001240102000000000272950000 -default

##### Installation options
 * `-default` - makes the applet default selected
 * `-terminate` - gives card lock and card terminate privileges to the applet
 * `-sdomain` - specifies security domain privilege
 * `-params <hex>` - installation parameters for applet

#### Lock / unlock usage

 * Set ```010B0371D78377B801F2D62AFC671D95``` key to a card with default ```40..4F``` keys:

        gp -lock 010B0371D78377B801F2D62AFC671D95

 * Set default ```40..4F``` keys to card that was previously locked with key ```010B0371D78377B801F2D62AFC671D95```:

        gp -key 010B0371D78377B801F2D62AFC671D95 -unlock
 
 * Set the default ```40..4F``` keys to a card that uses EMV diversification (like G&D):

        gp -emv -unlock
 
    \* note that you will have to use ```--relax``` option after this operation to get rid of the warning about probably needed diversification, which is not true any more.

 * Set the default ```40..4F``` keys to a card that uses VISA2 diversification with the well-known mother key on a Gemalto card:

        gp -visa2 -key 47454D5850524553534F53414D504C45 -unlock -mode clr

#### Debugging options

 * Show APDU-s sent to the card:
   
   add ```-debug``` or ```-d``` to your command

 * Be more verbose about decisions and conditions:
   
   add ```-verbose``` or ```-v``` to your command

 * Don't use MAC on commands (plain GlobalPlatform syntax):

   add ```-mode clr``` to your command (not supported on all cards)

 * Show all options recognized by ```gp``` utility:

   add ```-help``` or ```-h``` or ```--help``` to your ```gp``` command

### Usage from Java
 * For now consult the [command line utility source code](https://github.com/martinpaljak/GlobalPlatformPro/blob/master/src/pro/javacard/gp/GPTool.java)
 * Rudimentary [Javadoc](http://martinpaljak.github.io/GlobalPlatformPro/)
 * General rules:
   * Expect ```RuntimeException```-s when things go unexpectedly wrong
   * ```CardException```-s when link layer fails
   * ```GPException```-s when protocol layer fails

### Supported cards
 * **NEW!** [JavaCard Buyer's Guide of 2016](https://github.com/martinpaljak/GlobalPlatformPro/tree/master/docs/JavaCardBuyersGuide)
 * See [TestedCards](https://github.com/martinpaljak/GlobalPlatformPro/tree/master/docs/TestedCards)
 * Generally speaking any modern JavaCard that speaks GlobalPlatform 2.1.1+
 * Available cards from all major vendors have been tested for basic compatibility: [Athena](http://www.athena-scs.com/), [Gemalto](http://www.gemalto.com/), [Giesecke & Devrient](http://www.gi-de.com/), [Infineon](http://www.infineon.com/), [NXP (JCOP)](http://www.nxp.com/), [Morpho](http://www.morpho.com/), [Oberthur](http://www.oberthur.com/)
   * If you are a smart card vendor please do *[get in touch](#contact)* for clarification and better support!

### History

The ancestor of this code is GPJ (Global Platform for SmartCardIO) which is (still) available from http://gpj.sourceforge.net. I started the project because I felt that messing with cryptic script files was not nice and I wanted to have a simple, open source, usable and native-to-the-rest-of-development-environment (Java) toolchain.


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
   * no new features or standards
 * GPShell + globalplatform library - http://sourceforge.net/projects/globalplatform/ (LGPL)
   * written in C
   * often referred to as the de facto open source GlobalPlatform implementation
   * several components need to be compiled and installed before usage
   * requires more complex "script files" and does not provide a direct command line utility
 * jcManager - http://www.brokenmill.com/2010/03/java-secure-card-manager/ (LGPL)
   * written in Java  
   * has a basic GUI
   * old and not maintained
 * gpjNG - https://github.com/SimplyTapp/gpjNG (LGPL)
   * fork of gpj with minor additions, mostly a "script mode" that makes it similar to GPShell
 * Ruby smartcard module - http://smartcard.rubyforge.org/classes/Smartcard/Gp/GpCardMixin.html (MIT)
   * written in Ruby
   * does not seem to expose all functionality (key diversification, key change etc)
   * no command line utility
 * JGPShell - https://sourceforge.net/projects/jgpshell/ (GPL2)
   * written in Java
   * GPShell-style scripting goal
   * not really usable and also abandoned
 * OPAL - https://bitbucket.org/ssd/opal (CeCILL, GPLv2 compatible)
   * written in Java
   * claims to have SCP03 support (but no tested cards)
   * looks "heavy" and over-engineered
   * smoke tests give exceptions and doesn't work on OSX nor Debian.
 * gpcomm - https://code.google.com/p/gpcomm/
   * written in Java
   * incomplete and abandoned
 * globalplatform.net - https://github.com/sepulo/globalplatform.net
   * written in c#
   * unclear license (missing)
   * only supports SCP01 and SCP02
 * asterix - https://github.com/suma12/asterix (LGPL 2.1)
   * written in Python
   * SCP02, SCP03
 * LuaGP - https://github.com/bondhan/LuaGP
   * written in Lua  
 * JCOP tools, RADIII, JCardManager4, JLoad, PyApduTool etc
   * not publicly available cross-platform open source projects and thus not suitable for this comparision

## Upcoming releases and major new features
 * **NEW!** Have a look at [milestones](https://github.com/martinpaljak/GlobalPlatformPro/milestones)
 * T+1 (v0.2.5)
   * ~~Re-written command line utility~~
   * ~~Windows .exe for ease of use~~
   * ~~-lock and -unlock commands for changing secure channel keys~~
 * T+2 (v0.3.0)
   * ~~SCP03 v1.1.1 and GP2.2.1~~
 * T+X (wishlist)
   * ~~Support for storing card management keys in PKCS#11 tokens (HSM)~~
   * GPShell-style scripts (instead of Java)
   * Simple GUI for basic operations/browsing

## Design principles
 * focus on real life and practical daily use cases
 * KISS, YAGNI, DWIM, no-NIH
 * APDU-chat over anything that extends `CardChannel` to (most probably real) tokens
 * thin and self-contained, re-usable, easy to integrate
 * easily readable, auditable and secure codebase (less is more)

## About
The promise of GlobalPlatformPro is similar to OpenSSL:
    
> Why buy a smart card **software kit as a black box** when you can get an **open one for free**?

In regard to GlobalPlatform, the goal is to make simple operations like installing and removing applets and locking the card with new keys as easy as next-next-done - you don't have to know the whole Global Platform specification by heart for that or buy a piece of proprietary software for a few hundred euros! For all those features that are not described in the GlobalPlatform specification that actually make your card work... you still have to use those proprietary commands, but OpenKMS GlobalPlatformPro toolkit's flexibility (and its license) should allow you to do that as well.

### License

 * [LGPL 3.0](http://www.gnu.org/licenses/lgpl-3.0.html) for derived code and MIT/LGPL3 for original code.

### Included/used open source projects

 * [BouncyCastle](http://pholser.github.io/jopt-simple/) for OID parsing and NIST SP 800-108/NIST SP 800-38B (MIT)
 * [JOpt Simple](http://pholser.github.io/jopt-simple/) for parsing command line (MIT)
 * [Launch4j](http://launch4j.sourceforge.net/) for generating the .exe (BSD/MIT)
 * [apdu4j](https://github.com/martinpaljak/apdu4j) for APDU access/logging/replaying (MIT)

### Contact 

* Generic enquiries: martin@martinpaljak.net
* **For technical support:**
  * re-run your failing command with ```-d -v -i``` switches and send the output, information about your card and applet/CAP
  * **Only plaintext** logs. **NO** screenshots, pictures, word documents. **NO** generic questions about java/linux/windows/globalplatform. Questions about jcshell/gpshell/gpj/something else **shall be ignored**.
  * If unsure, first read about [asking questions](http://www.catb.org/esr/faqs/smart-questions.html)
* [File an issue on Github](https://github.com/martinpaljak/GlobalPlatformPro/issues/new). Better yet - a pull request!
* Want to **donate**? E-mail or paypal to martin@martinpaljak.net

#### Legal disclaimer
 The casual: trademarks to their owners, copyrights to authors, software patents to hell, legal letters to ~~/dev/null~~ PGP key 0x307E3452. Everything is provided AS-IS AND THERE IS A CONSTANT RISK OF DEATH FROM SUDDEN LIGHTNING. Writing in all caps made it look like serious, didn't it?

----
[JavaCard.pro](http://javacard.pro)
