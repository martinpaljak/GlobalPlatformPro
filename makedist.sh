#!/bin/sh
TODAY=`date +%Y%m%d`
NAME=gpj-$TODAY
mkdir $NAME
cp -r README.txt lgpl*.txt gpj.bat gpj.sh gpj.jar $NAME
zip -r $NAME.zip $NAME
rm -rf $NAME


