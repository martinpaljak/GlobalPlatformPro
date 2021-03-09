#!/bin/bash
# Starting point with G&D SCE 7.0
# ISD: SECURED
# Keyset version 1: 40..4F keys
# DelegatedManagement key set to library/src/test/resources/test-dm-rsa-1k.pem 
set -e
export GP_READER=${GP_READER:-piiksuga}
CAP=tests/Empty_0102030405_8d5ac9e2_2.2.1.cap
DMKEY=library/src/test/resources/test-dm-rsa-1k.pem
ISD=A000000003000000
PKG=0102030405
export GP_TRACE=true
GP="java -jar ./tool/target/gp.jar -dv"

# Load and unload an applet
$GP -key default -install $CAP
$GP -key default -uninstall $CAP

# create simple domain
DOM=010101010101
$GP -key default -domain $DOM --allow-to --allow-from

# lock it
$GP -connect $DOM -key default -lock emv:default

# Load applet into it
$GP -key default -load $CAP -to $DOM

# Create domain with delegated management support
DOM2=020202020202
$GP -key default -domain $DOM2 -privs DelegatedManagement -allow-to --allow-from

# Lock with visa2 KDF
$GP -connect $DOM2 -key default -lock emv:default

# Move package from $DOM to $DOM2 (or DM would fail)
$GP -key default -move $PKG -to $ISD

# Create instance of applet with DM, in ISD
INSTANCE=030403040304
$GP -connect $DOM2 -key emv:default -cap $CAP -create $INSTANCE -dm-key $DMKEY

# Create domain with authorized management support
DOM3=030303030303
$GP -key default -domain $DOM3 -privs AuthorizedManagement --allow-to

# Set default keys
$GP -connect $DOM3 -key default -lock default

# Move instance from $DOM2 to $DOM3
$GP -key default -move $INSTANCE -to $DOM3

# Delete instance with AM
$GP -connect $DOM3 -key default -delete $INSTANCE


# Delete everything
$GP -delete $PKG -delete $DOM3 -delete $DOM2 -delete $DOM

