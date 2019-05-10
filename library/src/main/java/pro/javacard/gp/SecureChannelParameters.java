/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2019 Martin Paljak, martin@martinpaljak.net
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

import apdu4j.HexUtils;
import pro.javacard.AID;

import java.util.Map;
import java.util.Optional;

public class SecureChannelParameters {

    private AID aid;

    private GPCardKeys cardKeys;

    public Optional<AID> getAID() {
        return Optional.ofNullable(aid);
    }

    public GPCardKeys getCardKeys() {
        return cardKeys;
    }

    public static Optional<SecureChannelParameters> fromEnvironment() {
        return fromKeyValuePairs(System.getenv());
    }

    public static Optional<SecureChannelParameters> fromKeyValuePairs(Map<String, String> env) {
        SecureChannelParameters params = new SecureChannelParameters();

        if (env.containsKey("GP_KEY_ENC") && env.containsKey("GP_KEY_MAC") && env.containsKey("GP_KEY_DEK")) {
            byte[] enc = HexUtils.stringToBin(env.get("GP_KEY_ENC"));
            byte[] mac = HexUtils.stringToBin(env.get("GP_KEY_MAC"));
            byte[] dek = HexUtils.stringToBin(env.get("GP_KEY_DEK"));
            params.cardKeys = PlaintextKeys.fromKeys(enc, mac, dek);
            if (env.containsKey("GP_KEY_VERSION")) {
                ((PlaintextKeys) params.cardKeys).setVersion(GPUtils.intValue(env.get("GP_KEY_VERSION")));
            }
            if (env.containsKey("GP_AID")) {
                params.aid = AID.fromString(env.get("GP_AID"));
            }
        } else {
            return Optional.empty();
        }
        return Optional.of(params);
    }
}
