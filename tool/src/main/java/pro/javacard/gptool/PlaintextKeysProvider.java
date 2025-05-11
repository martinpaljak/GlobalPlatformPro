/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2020-present Martin Paljak, martin@martinpaljak.net
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
package pro.javacard.gptool;

import apdu4j.core.HexUtils;
import com.google.auto.service.AutoService;
import pro.javacard.gp.CardKeysProvider;
import pro.javacard.gp.GPCardKeys;
import pro.javacard.gptool.keys.PlaintextKeys;

import java.util.Map;
import java.util.Optional;

@AutoService(CardKeysProvider.class)
public class PlaintextKeysProvider implements CardKeysProvider {

    public PlaintextKeysProvider() {
    }

    @Override
    public Optional<GPCardKeys> getCardKeys(String spec) {
        if (spec == null)
            return Optional.empty();
        spec = spec.trim();
        try {
            // <kdf>:<hex> or <kdf>:default
            for (Map.Entry<String, String> d : PlaintextKeys.kdf_templates.entrySet()) {
                if (spec.toLowerCase().startsWith(d.getKey())) {
                    byte[] k = hexOrDefault(spec.substring(d.getKey().length() + 1));
                    return Optional.of(PlaintextKeys.fromMasterKey(k, d.getValue()));
                }
            }

            // <hex> or "default"
            byte[] k = hexOrDefault(spec);
            return Optional.of(PlaintextKeys.fromMasterKey(k));
        } catch (IllegalArgumentException e) {
            // log
        }
        return Optional.empty();
    }

    static byte[] hexOrDefault(String v) {
        if ("default".startsWith(v.toLowerCase()))
            return PlaintextKeys.DEFAULT_KEY();
        return HexUtils.stringToBin(v);
    }
}
