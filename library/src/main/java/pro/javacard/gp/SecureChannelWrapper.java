// SPDX-FileCopyrightText: 2015 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;

import java.util.EnumSet;

abstract class SecureChannelWrapper {
    protected final int blockSize;
    protected byte[] encKey;
    protected byte[] macKey;
    protected byte[] rmacKey;
    protected boolean mac;
    protected boolean enc;
    protected boolean rmac; // could be sessions
    protected boolean renc;

    protected SecureChannelWrapper(byte[] enc, byte[] mac, byte[] rmac, int bs) {
        this.mac = true; // we always start in mac mode for external authenticate
        encKey = enc.clone();
        macKey = mac.clone();
        if (rmac != null) {
            rmacKey = rmac.clone();
        }
        blockSize = bs;
    }

    protected int getBlockSize() {
        var res = this.blockSize;
        if (mac) {
            res = res - 8;
        }
        if (enc) {
            res = res - 8;
        }
        return res;
    }

    abstract CommandAPDU wrap(CommandAPDU command) throws GPException;

    abstract ResponseAPDU unwrap(ResponseAPDU response) throws GPException;

    void setSecurityLevel(final EnumSet<GPSession.APDUMode> securityLevel) {
        mac = securityLevel.contains(GPSession.APDUMode.MAC);
        enc = securityLevel.contains(GPSession.APDUMode.ENC);
        rmac = securityLevel.contains(GPSession.APDUMode.RMAC);
        renc = securityLevel.contains(GPSession.APDUMode.RENC);
    }
}
