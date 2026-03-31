@SuppressWarnings({"requires-automatic"})
module gptool.nextgen {
    requires pro.javacard.globalplatform;
    requires pro.javacard.pace;
    requires pro.javacard.tlv;
    requires apdu4j.apdulette;

    requires apdu4j.prefs;
    requires apdu4j.pcsc;
    requires jopt.simple;
    requires com.fasterxml.jackson.core;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.dataformat.cbor;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires org.slf4j;

    provides pro.javacard.gp.ToolExtension
        with pro.javacard.gp.ng.GPToolNG;
}
