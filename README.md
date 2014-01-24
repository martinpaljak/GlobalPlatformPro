GlobalPlatform for OpenKMS
==========================
Load and manage applets with GlobalPlatform compatible JavaCards
### Usage
Command line samples assume default test keys of ```40..4F```. If you need custom keys, specify them with any or all of the following options: ```-keyid``` ```-keyver``` ```-enc``` ```-mac``` ```-kek``` (you need to know the details or ask your card provider). Some cards require key diversification with ```-emv``` or ```-visa2``` (you should be notified if that's the case).

 * Show some basic information about a card (failsafe):

        java -jar openkms-globalplatform.jar -info

 * List applets:

        java -jar openkms-globalplatform.jar -list

 * Delete current default applet:

        java -jar openkms-globalplatform.jar -delete -default

 * Install applet.cap as default applet (with information from the CAP):

        java -jar openkms-globalplatform.jar -load applet.cap -install -default
 
 * Show APDU-s sent to the card:
   
   add ```-debug``` to your command

 * Don't use MAC on commands (plain GlobalPlatform commands):
   add ```-mode clr``` to your command (not supported on all cards)


### Contact 

 * martin@martinpaljak.net
 * .. or file an issue on Github

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

-- 
OpenKMS - open source key management - [openkms.org](http://openkms.org)
