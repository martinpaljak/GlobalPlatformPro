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

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.nio.ByteBuffer;
import java.util.EnumSet;

abstract class SecureChannelWrapper {
    protected int blockSize = 0;
    protected GPSessionKeyProvider sessionKeys = null;
    protected boolean mac = false;
    protected boolean enc = false;
    protected boolean rmac = false;
    protected boolean renc = false;


    public void setSecurityLevel(EnumSet<GlobalPlatform.APDUMode> securityLevel) {
        mac = securityLevel.contains(GlobalPlatform.APDUMode.MAC);
        enc = securityLevel.contains(GlobalPlatform.APDUMode.ENC);
        rmac = securityLevel.contains(GlobalPlatform.APDUMode.RMAC);
        renc = securityLevel.contains(GlobalPlatform.APDUMode.RENC);
    }

    protected int getBlockSize() {
        int res = this.blockSize;
        if (mac)
            res = res - 8;
        if (enc)
            res = res - 8;
        return res;
    }

    protected abstract CommandAPDU wrap(CommandAPDU command) throws GPException;

    protected abstract ResponseAPDU unwrap(ResponseAPDU response) throws GPException;
}
