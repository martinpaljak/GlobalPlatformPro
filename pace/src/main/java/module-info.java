@SuppressWarnings({"requires-automatic", "requires-transitive-automatic"})
module pro.javacard.pace {
    requires transitive apdu4j.core;
    requires ber.tlv;
    requires org.bouncycastle.pkix;
    requires transitive org.bouncycastle.provider;
    requires org.slf4j;

    exports pro.javacard.pace;
}