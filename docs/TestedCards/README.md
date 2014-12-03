NOTICE: a JavaCard shall be listed here as "supported" if and only if:
* It is available from some verified webshop, in small quantities (like 1, 3, 5 or 10)
* Comes with default keys or otherwise known keys and OP_READY state
* Has been verified as working for at least a "load-install-lock-uninstall-unlock" cycle

TIP: When ordering cards online, always make sure that you ask for cards with default keys

## Supported cards (with a confirmed shop link)
* [SmartCafe Expert 3.2 72K JavaCard 2.2.1/GlobalPlatform 2.1.1 12€](http://www.smartcardfocus.com/shop/ilp/id~521/SmartCafe_Expert_3_2_72K/p/index.shtml)
  * and other products with same name but different EEPROM + connectivity
* [Yubikey NEO CCID JavaCard 3.0.X/GlobalPlatform 2.1.1 50$](https://store.yubico.com/store/catalog/index.php?cPath=21) **NB** Newer tokens [do not come with public GlobalPlatform keys](https://www.yubico.com/2014/07/yubikey-neo-updates/) and thus the token is not usable! You can try asking for a developer version though.
  * This is a USB token
* [JCOP J3D081 v2.4.2 JavaCard 3.0.1/GlobalPlatform 2.2 40€](http://www.motechno.com/javacard3.0.html)

## More cards that should work but wait confirmation
* [GEMALTO IDCORE 10 - GEMALTO TOP IM GX4 JavaCard 2.2.1/GlobalPlatform 2.0.1 16€] (http://www.cryptoshop.com/gemalto-idcore-10-gemalto-top-im-gx4.html)
  * Works flawlessly. Virgin cars require unlocking with "-visa2 -key <motherkey>"
  * Unlocking only works in clear mode (-mode clr) for some reason.
  * Instead of a reasonable error code a failed transaction is returned on errors.
* [GEMALTO IDCORE 3010 CC / TOP DM CC 25€](http://www.cryptoshop.com/gemalto-top-dm-cc.html)

## Tested cards without a confirmed shop link
* Oberthur Cosmo v7 128K JavaCard 2.2.2/GlobalPlatform 2.1.1 (smartcardfocus.com used to sell it)
* [JCOP31 v2.4.1 JavaCard 2.2.2/GlobalPlatform 2.1.1 18€] (like this: http://www.cryptoshop.com/jcop-31-v2-4-1-72k.html)
* [Athena ID-protect JC2.2.2/GP2.1.1 29€](http://www.cryptoshop.com/idprotect-key-usb-nano-laser.html)
 * Or this: http://www.cryptoshop.com/athena-idprotect-java-card-bio-match-on-card.html
 * See this http://www.athena-scs.com/docs/products-solutions-datasheets/athena-idprotect-laser.pdf
* [JCOP v2.4.1 NXP J3A080 Dual Interface Card (10 pcs.) 110€](https://www.united-access.com/javacard)
* [Gemalto TOP IM FIPS CY2 £14.00](http://smartware2u.com/products/30-gemalto-top-im-fips-cy2.aspx)


## More information about different cards
 * http://www.fi.muni.cz/~xsvenda/jcsupport.html