#!/bin/sh

TODAY=`date +%Y%m%d`
NAME=gpj-$TODAY

mkdir $NAME

cp -r README.txt lgpl*.txt gpj.bat gpj.sh gpj.jar $NAME

sed --in-place 's/$/\r/' $NAME/*.txt $NAME/*.bat

rm -rf `find $NAME -name ".svn"`

zip -r $NAME.zip $NAME

rm -rf $NAME


