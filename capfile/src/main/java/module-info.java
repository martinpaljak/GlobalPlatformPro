module pro.javacard.capfile {
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;

    requires java.xml;
    requires org.yaml.snakeyaml;

    exports pro.javacard.capfile;
    exports pro.javacard.sdk;
}