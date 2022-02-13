module pro.javacard.globalplatform {
    requires apdu4j.core;
    requires ber.tlv;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider; // FIXME: Hex. uses this
    requires org.slf4j;
    requires pro.javacard.capfile;

    exports pro.javacard.gp;
}