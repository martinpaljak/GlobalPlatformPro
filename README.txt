FIRST IMPORTANT NOTE
====================

The author(s) of this project and software included within are not in
any way responsible for your broken cards when you use my software. GP
compliant smart cards are very sensitive to failed authentication
attempts and may become unoperational. So make sure you know what you
are doing. The library has been tested with a handful of OP2.0.1 and
GP2.1.1 cards, but this does not guarantee proper operation with your
particular card!


INTRODUCTION
============

This is the current release of the Global Platform for SmartCardIO
Java SDK library, http://gpj.sourceforge.net. It provides a library
for GP compliant communication with GP compliant smart cards - listing
contents, applet loading and deletion, etc. The library is under
development and is currently concentrated on the above mentioned
features. That is, e.g.  GP key loading or manipulation is not yet
implemented. A command line host application for managing applets on
the card is included. Functionality wise this project provides very
similar facilities as http://globalplatform.sourceforge.net and their
gpshell application. Only this one is in pure Java and connects
directly to SmartCardIO.

AUTHOR(S)
=========

This project has been developed by Wojciech Mostowski <woj@cs.ru.nl>,
and Francois Kooman <F.Kooman@student.science.ru.nl> from Radboud
University Nijmegen, the Netherlands. The project uses some code
written ages ago by Martijn Oostdijk
<martijn.oostdijk@gmail.com>.

REQUIREMENTS
============

To use the library or the host application you need Java Runtime
Environment 1.6.  For portability reasons (e.g. to Nokia NFC phones)
the library also uses the Bouncy Castle crypto provider, see
http://www.bouncycastle.org. However, Bouncy Castle is not required to
run the library or the application on JDK 1.6.

SOURCE CODE, LICENSE
====================

The source code is released under LGPL and is currently only available
from the SourceForge SVN repository, see

https://sourceforge.net/scm/?type=svn&group_id=273978

The libraries that we use are released under respective licenses
described in the "lib" folder.

RUNNING THE GP APPLICATION
==========================

Unpack the release file (you must have done that already since you are
reading this file). Run (or use provided Linux or Windows scripts):

  java -jar gpj.jar

to get the list of available options for the applet manipulation
program.

SOME EXAMPLES
=============

To list the applets on the cards simply say (assuming default
authentication and keys):

  java -jar gpj.jar -list

To delete an applet from the card say:

  java -jar gpj.jar -delete <AID>

To install a new applet on the card (with default install parameters),
say:

  java -jar gpj.jar -load <capFile> -install

THANKS
======

Hendrik Tews for contributing some code.
