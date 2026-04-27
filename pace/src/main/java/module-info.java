// SPDX-FileCopyrightText: 2024 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

@SuppressWarnings({"requires-automatic", "requires-transitive-automatic"})
module pro.javacard.pace {
    requires transitive apdu4j.core;
    requires pro.javacard.tlv;
    requires org.bouncycastle.pkix;
    requires transitive org.bouncycastle.provider;
    requires org.slf4j;

    exports pro.javacard.pace;
}