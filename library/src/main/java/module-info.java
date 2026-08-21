// SPDX-FileCopyrightText: 2022 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

// https://stackoverflow.com/a/67895919/44289
@SuppressWarnings({"requires-automatic"})
module pro.javacard.globalplatform {
    requires transitive apdu4j.core;

    requires transitive pro.javacard.tlv; // GPCertificate.fields() hands out TLV
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider; // FIXME: Hex. uses this
    requires transitive org.slf4j;
    requires transitive pro.javacard.capfile;

    exports pro.javacard.gp;
    exports pro.javacard.gp.emv;
    exports pro.javacard.gp.keys;
    exports pro.javacard.gp.data;
}
