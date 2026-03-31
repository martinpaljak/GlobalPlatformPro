/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2026-present Martin Paljak, martin@martinpaljak.net
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
 *
 */
package pro.javacard.gp.ng;

import apdu4j.core.BIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import pro.javacard.gp.GPUtils;

import java.io.ByteArrayOutputStream;

// Shared utilities for secure channel implementations
final class SecureChannels {

    private SecureChannels() {}

    // APDU chaining (GPC 2.3.1 11.1.5.1)
    // If wrapped command data exceeds physical block size, split into chained APDUs
    static BIBO withChaining(final BIBO bibo, final int blockSize) {
        return new BIBO() {
            @Override
            public byte[] transceive(final byte[] bytes) {
                var cmd = new CommandAPDU(bytes);
                if (cmd.getNc() <= blockSize) {
                    return bibo.transceive(bytes);
                }
                var chunks = GPUtils.splitArray(cmd.getData(), blockSize);
                byte[] response = null;
                for (var i = 0; i < chunks.size(); i++) {
                    var last = i == chunks.size() - 1;
                    var p1 = last ? cmd.getP1() : cmd.getP1() | 0x80;
                    var chained = new CommandAPDU(cmd.getCLA(), cmd.getINS(), p1, cmd.getP2(), chunks.get(i), 256);
                    response = bibo.transceive(chained.getBytes());
                    if (!last) {
                        var sw = new ResponseAPDU(response).getSW();
                        if (sw != 0x9000) {
                            return response;
                        }
                    }
                }
                return response;
            }

            @Override
            public void close() {
                bibo.close();
            }
        };
    }

    static CommandAPDU assembleAPDU(final int cla, final CommandAPDU original, final byte[] data, final byte[] macBytes) {
        final var out = new ByteArrayOutputStream();
        out.writeBytes(data);
        if (macBytes != null) {
            out.writeBytes(macBytes);
        }
        if (original.getNe() > 0) {
            return new CommandAPDU(cla, original.getINS(), original.getP1(), original.getP2(), out.toByteArray(), original.getNe());
        } else {
            return new CommandAPDU(cla, original.getINS(), original.getP1(), original.getP2(), out.toByteArray());
        }
    }
}
