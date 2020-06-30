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
package pro.javacard.gp;

import apdu4j.HexUtils;
import com.google.auto.service.AutoService;
import pro.javacard.gp.i.CardKeysProvider;

import java.util.Optional;

@AutoService(CardKeysProvider.class)
public class PlaintextKeysProvider implements CardKeysProvider {

    @Override
    public Optional<GPCardKeys> getCardKeys(String spec) {
        for (PlaintextKeys.Diversification d : PlaintextKeys.Diversification.values()) {
            if (spec.toLowerCase().startsWith(d.name().toLowerCase())) {
                byte[] k = HexUtils.stringToBin(spec.substring(d.name().length() + 1));
                return Optional.of(PlaintextKeys.derivedFromMasterKey(k, null, d));
            }
        }
        try {
            byte[] k = HexUtils.stringToBin(spec);
            return Optional.of(PlaintextKeys.fromMasterKey(k));
        } catch (IllegalArgumentException e) {
            // log
        }
        return Optional.empty();
    }
}
