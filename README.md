# GlobalPlatformPro - _the_ Swiss Army Knife for JavaCard-s
[![LGPL-3.0 licensed](https://img.shields.io/badge/license-LGPL-blue.svg)](https://github.com/martinpaljak/GlobalPlatformPro/blob/master/LICENSE)
&nbsp;[![Latest release](https://img.shields.io/github/release/martinpaljak/GlobalPlatformPro.svg)](https://github.com/martinpaljak/GlobalPlatformPro/releases/latest)
&nbsp;[![Maven version](https://img.shields.io/maven-metadata/v?label=maven&metadataUrl=https%3A%2F%2Fmvn.javacard.pro%2Fmaven%2FSNAPSHOTS%2Fcom%2Fgithub%2Fmartinpaljak%2Fglobalplatformpro%2Fmaven-metadata.xml)](https://gist.github.com/martinpaljak/c77d11d671260e24eef6c39123345cae)
&nbsp;[![Build status](https://github.com/martinpaljak/globalplatformpro/actions/workflows/robot.yml/badge.svg?branch=master)](https://github.com/martinpaljak/globalplatformpro/actions)
&nbsp;[![Made in Estonia](https://img.shields.io/badge/Made_in-Estonia-blue)](https://estonia.ee)

Load and manage applets and keys on JavaCards from command line or from your Java project with a [Do What I Mean](http://en.wikipedia.org/wiki/DWIM) approach ([testimonials](https://github.com/martinpaljak/GlobalPlatformPro/wiki/Testimonials)).

GPPro provides an **easy to use** and **high level** interface that most of the time **JustWorks<sup>(TM)</sup>**, is **flexible** and **[100% open source](#license)**!


```
$ gp -install HelloWorld.cap -privs CardReset -params 48692074686572652C2077686174277320796F7572206E616D653F
# Warning: no keys given, defaulting to 404142434445464748494A4B4C4D4E4F
HelloWorld.cap loaded: com.example.helloworld A048656C6C6F576F726C64

$ gp -l
# Warning: no keys given, defaulting to 404142434445464748494A4B4C4D4E4F
ISD: A000000151000000 (OP_READY)
     Parent:   A000000151000000
     From:     A0000001515350
     Privs:    SecurityDomain, CardLock, CardTerminate, CVMManagement, TrustedPath, AuthorizedManagement, TokenVerification, GlobalDelete, GlobalLock, GlobalRegistry, FinalApplication, ReceiptGeneration

APP: A048656C6C6F576F726C64 (SELECTABLE) (|.HelloWorld|)
     Parent:   A000000151000000
     From:     A048656C6C6F576F726C64
     Privs:    CardReset

PKG: A0000001515350 (LOADED) (SSD creation package)
     Parent:   A000000151000000
     Version:  255.255
     Applet:   A000000151535041 (SSD creation applet)

PKG: A0000000620204 (LOADED) (javacardx.biometry1toN)
     Parent:   A000000151000000
     Version:  1.0

PKG: A0000000620202 (LOADED) (javacardx.biometry)
     Parent:   A000000151000000
     Version:  1.3

PKG: A048656C6C6F576F726C6401 (LOADED) (|.HelloWorld.|)
     Parent:   A000000151000000
     Version:  1.0
     Applet:   A048656C6C6F576F726C64 (|.HelloWorld|)

```

It's that simple!

> [!TIP]
> Building JavaCard applets is equally pleasing with **[ant-javacard](https://github.com/martinpaljak/ant-javacard)**


## NEWS &middot; `Q4 2024`
 - [JavaCard Buyer's Guide](https://github.com/martinpaljak/GlobalPlatformPro/wiki/JavaCard-Buyer%27s-Guide) has been updated to 2024
 - GlobalPlatformPro v24.10.15 released with many new features
   - enhanced support for Delegated Management and DAP keys
   - receipt verification
   - PACE authentication and secure channel
   - Key Diversification templates
   - S16 mode for SCP03
   - many bugs fixed, UX improved.

# Start from [Getting Started guide](https://github.com/martinpaljak/GlobalPlatformPro/wiki/Getting-Started) in the wiki

> [!IMPORTANT]
> 1. Use it?
>    - Add a ⭐
> 2. Like it?
>    - **[Become a sponsor](https://github.com/sponsors/martinpaljak)**

### License

 * [LGPL-3.0](https://github.com/martinpaljak/GlobalPlatformPro/blob/master/LICENSE) for derived code and MIT/LGPL3 for original code.

## Contact
Professional support is available from [javacard.pro](https://javacard.pro). For community help, please check [Support & Questions](https://github.com/martinpaljak/GlobalPlatformPro/wiki/Support-%26-Questions) section in the wiki.
