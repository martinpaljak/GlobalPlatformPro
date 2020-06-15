/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2018 Martin Paljak, martin@martinpaljak.net
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package pro.javacard.gp;

import apdu4j.CommandAPDU;
import apdu4j.ResponseAPDU;

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


    protected SecureChannelWrapper(byte[] enc, byte[] mac, byte[] rmac, EnumSet<GPSession.APDUMode> securityLevel, int bs) {
        setSecurityLevel(securityLevel);
        encKey = enc.clone();
        macKey = mac.clone();
        if (rmac != null)
            rmacKey = rmac.clone();
        blockSize = bs;
    }

    protected int getBlockSize() {
        int res = this.blockSize;
        if (mac)
            res = res - 8;
        if (enc)
            res = res - 8;
        return res;
    }

    abstract CommandAPDU wrap(CommandAPDU command) throws GPException;

    abstract ResponseAPDU unwrap(ResponseAPDU response) throws GPException;

    void setSecurityLevel(EnumSet<GPSession.APDUMode> securityLevel) {
        mac = securityLevel.contains(GPSession.APDUMode.MAC);
        enc = securityLevel.contains(GPSession.APDUMode.ENC);
        rmac = securityLevel.contains(GPSession.APDUMode.RMAC);
        renc = securityLevel.contains(GPSession.APDUMode.RENC);
    }
}
