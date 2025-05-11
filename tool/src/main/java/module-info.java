// https://stackoverflow.com/a/67895919/44289
@SuppressWarnings({"requires-automatic"})
module gptool {
    requires transitive pro.javacard.globalplatform;
    requires pro.javacard.pace;
    requires java.smartcardio;
    requires jopt.simple;
    requires com.google.auto.service;
    requires apdu4j.pcsc;
    requires ber.tlv;
    requires com.fasterxml.jackson.core;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.dataformat.cbor;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires org.slf4j;

    exports pro.javacard.gptool.keys;
}