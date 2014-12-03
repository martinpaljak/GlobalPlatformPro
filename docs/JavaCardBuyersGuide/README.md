# JavaCard Buyer's Guide of winter 2014/2015

JavaCard is an *almost-a-commodity* platform for creating small applications that run inside a smart card chip. Such applications usually deal with handling of cryptographic keys or otherwise processing cryptographic secrets.

This is a cheat sheet for buying blank, **developer-friendly JavaCard-s from the Internet**. It comes as-is, with no endorsements nor warranty!

## What to ask / look out for
 * **JavaCard version**: 2.2.2, with 3.0.1 and 3.0.4 becoming popular. **Bigger is better** but for actual rollout check the necessary features, algorithms and maybe try to aim for 2.2.2-compatible code.
 * **GlobalPlatform version**: 2.1.1 and 2.2 are common. This relates to loading your application to the card and 2.1.1 is sufficient, while 2.2 adds SCP03 support, which uses AES instead of 3DES. Note: GlobalPlatform tool currently only speaks 3DES keys and SCP01/SCP02.
 * **EEPROM size**: 64K, 72K, 128K, 144K and bigger sizes are common. **Bigger is better**, but when actually rolling out your card, choose a size that is with optimal price/size depending on actual requirements.
 * **GlobalPlatform default keys** (or **test keys**, with the value ```404142434445464748494A4B4C4D4E4F``` or ```40..4F``` for short): only if you get default test keys (or otherwise known keys) shall you be able to load applications to the card. You **shall not be able to load your application to the card without the keys**. Always be sure to ask for test keys for sample cards!
 * **Contact/Contactless interface**: for creating NFC applications you want to get a card with **dual interface** or even contactless-only.
 * **Proximity cards**: for opening doors, usually a different chip is present on the card for this single purpose. But a vendor can usually combine necessary physical access cards with a suitable JavaCard chip module.

## Manufacturers
See also: [Java Card Forum](http://javacardforum.com/)

Known manufacturers of JavaCard compatible smart cards, in alphabetical order:

 * [Athena](http://www.athena-scs.com/)
 * [Feitian](http://www.ftsafe.com/)
 * [Gemalto](http://www.gemalto.com/)
 * [Giesecke & Devrient](http://www.gi-de.com/)
 * [Infineon](http://www.infineon.com/)
 * [Morpho](http://www.morpho.com/)
 * [NXP (JCOP)](http://www.nxp.com/)
 * [Oberthur](http://www.oberthur.com/)
  

## Shops that sell JavaCard-s
In alphabetical order:

 * [CryptoShop](http://www.cryptoshop.com/) (AT)
 * [MoTechno](http://www.motechno.com/) (DE)
 * [SmartcardFocus](http://www.smartcardfocus.com/) (UK, US)

## Checking for compatibility

[TestedCards](https://github.com/martinpaljak/GlobalPlatform/wiki/TestedCards) contains a list of smart cards that have been checked to work with the [GlobalPlatform tool](https://github.com/martinpaljak/GlobalPlatform#globalplatform-from-openkms). Simple ```gp -l``` should get you going.

## Need help ?

Contact [@martinpaljak](https://github.com/martinpaljak) with tips and questions by e-mailing martin@martinpaljak.net