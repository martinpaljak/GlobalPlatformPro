# JavaCard Buyer's Guide of 2018

JavaCard is an *almost-a-commodity* software platform for creating small applications that run inside a smart card chip. Such applications usually deal with handling of cryptographic keys or otherwise processing cryptographic secrets. While somewhat an open platform with public documentation, a lot is still proprietary and/or covered with broad NDA-s.

This is a cheat sheet for buying blank, **developer-friendly JavaCard-s from the Internet**. It comes **AS-IS**, with no endorsements nor warranty!

## What to ask / look out for
 * **JavaCard version**: 3.0.1 should be the minimum these days. Cards with 3.0.4 are also slowly becoming available and 3.0.5 specification is published but probably not available in real life production chips before a year or so. **Bigger is better**, but for actual rollout check the necessary features, algorithms and maybe try to aim for 2.2.2-compatible code. Keep in mind that API compatibility does not relate to algorithm availability!
 * **GlobalPlatform version**: 2.1.1 and 2.2.1 are common. This relates to loading your application to the card (for which 2.1.1 is sufficient) but 2.2 adds SCP03 support, which uses AES instead of 3DES. In addition to version and SCP algorithm, make sure that the card supports necessary features like RMAC or security domains or delegated management.
 * **EEPROM size**: 64K, 72K, 128K, 144K and bigger sizes are common. **Bigger is better**, but when actually rolling out your card, choose a size that is with optimal price/size depending on actual requirements.
 * **GlobalPlatform default keys** (or **test keys**, with the value ```404142434445464748494A4B4C4D4E4F``` or ```40..4F``` for short): only if you get default test keys (or otherwise known keys) shall you be able to load applications to the card. You **shall not be able to load your application to the card without the keys**. *Always* be sure to ask for test keys for sample cards! If a key diverisification scheme is used, get a reference to the method (EMV and VISA2 are known) and source of derivation data!
 * **Contact/Contactless interface**: for creating NFC applications you want to get a card with **dual interface** or even contactless-only. Pay attention to ISO 14443 *A* vs *B*!
 * **Proximity cards**: for opening doors, usually a different chip with a separate antenna is present on the card for this single purpose (especially for 125kHz). But a vendor can usually combine necessary physical access cards with a suitable JavaCard chip module. For Mifare Classic and DESFire emulation option is available with some chips.
 * **Common Criteria / FIPS / EMVCo validation**: most *serious* smart cards have some form of certification. CC EAL5+ and FIPS 140 level 3 being common for the JavaCard part. **Bigger is better** but keep in mind, that "the use of a validated cryptographic module in a computer or telecommunications system does not guarantee the security of the overall system." (excerpt from FIPS 140-2)
 * **GlobalPlatform lifecycle**: should be OP_READY, but keep in mind that certain pre-personalization steps (like changin physical characteristics of the chip) may only be done before this state and are usually proprietary. Keep this in mind when actually rolling out.
 * **SIM cards**: many if not all SIM (UICC) cards are JavaCard. Mapping guidelines exist, but SIM related functionality is usually independent of the programmable JavaCard part. SIM toolkit and similar packages must be available on the SIM.

## Manufacturers
See also: [Java Card Forum](http://javacardforum.com/)

Known manufacturers of JavaCard compatible smart cards, in alphabetical order:

 * [Athena](http://www.athena-scs.com/) ([acquired by NXP](http://media.nxp.com/phoenix.zhtml?c=254228&p=irol-newsArticle&ID=2118036))
 * [Feitian](http://www.ftsafe.com/)
 * [Gemalto](http://www.gemalto.com/)
 * [Giesecke & Devrient](http://www.gi-de.com/)
 * [Idemia](http://www.idemia.com/) (merger of Oberthur + Morpho)
 * [Infineon](http://www.infineon.com/)
 * [Morpho](http://www.morpho.com/) (merged with Oberthur, now Idemia)
 * [NXP (JCOP)](http://www.nxp.com/)
 * [Oberthur](http://www.oberthur.com/) (merged with Morpho, now Idemia)
  

## Shops that sell JavaCard-s
Also in small quantities. In alphabetical order:

 * [CryptoShop](http://www.cryptoshop.com/) (AT)
 * [MoTechno](http://www.motechno.com/) (DE)
 * [SmartcardFocus](http://www.smartcardfocus.com/) (UK, US)
 * [SmartcardSource](http://www.smartcardsource.com/) (CA)

## Checking for compatibility

[TestedCards document](https://github.com/martinpaljak/GlobalPlatformPro/tree/master/docs/TestedCards) contains a list of smart cards that have been checked to work with [GlobalPlatformPro tool](https://github.com/martinpaljak/GlobalPlatformPro). Simple ```gp -l``` should get you going.

## Similar documents
 * OpenDNSSEC 2012 [HSM Buyers' Guide](https://wiki.opendnssec.org/display/DOCREF/HSM+Buyers%27+Guide)
   * Similar overview from 2010 ([PDF](http://www.opendnssec.org/wp-content/uploads/2011/01/A-Review-of-Hardware-Security-Modules-Fall-2010.pdf))

## Need help ?

Contact [@martinpaljak](https://github.com/martinpaljak) with tips and questions by e-mailing martin@martinpaljak.net


**TO BE CONTINUED**
