// https://stackoverflow.com/a/67895919/44289
@SuppressWarnings({"requires-automatic"})
module gptool {
    requires transitive pro.javacard.globalplatform;
    requires pro.javacard.pace;
    requires java.smartcardio;
    requires jopt.simple;
    requires apdu4j.pcsc;
    requires pro.javacard.tlv;
    requires com.fasterxml.jackson.core;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.dataformat.cbor;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires org.slf4j;
}
