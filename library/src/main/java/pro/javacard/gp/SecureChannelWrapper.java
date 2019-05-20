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
    protected final GPSessionKeys sessionKeys;
    protected final boolean mac;
    protected final boolean enc;
    protected final boolean rmac; // could be sessions
    protected final boolean renc;


    protected SecureChannelWrapper( GPSessionKeys keys, EnumSet<GPSession.APDUMode> securityLevel, int bs) {
        mac = securityLevel.contains(GPSession.APDUMode.MAC);
        enc = securityLevel.contains(GPSession.APDUMode.ENC);
        rmac = securityLevel.contains(GPSession.APDUMode.RMAC);
        renc = securityLevel.contains(GPSession.APDUMode.RENC);
        sessionKeys = keys;
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
}
