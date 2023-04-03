// https://stackoverflow.com/a/67895919/44289
@SuppressWarnings({"requires-automatic"})
module pro.javacard.globalplatform {
    requires transitive apdu4j.core;
    requires ber.tlv;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider; // FIXME: Hex. uses this
    requires org.slf4j;
    requires transitive pro.javacard.capfile;

    exports pro.javacard.gp;
}