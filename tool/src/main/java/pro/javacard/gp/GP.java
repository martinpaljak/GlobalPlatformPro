/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2020 Martin Paljak, martin@martinpaljak.net
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

import apdu4j.BIBO;
import apdu4j.i.SmartCardApp;
import com.google.auto.service.AutoService;

/**
 * Provides an apdu4j compatible SmartCardApp interface
 */
@AutoService(SmartCardApp.class)
public final class GP implements SmartCardApp {

    // Public constructor for service initialization
    public GP() {
    }

    @Override
    public int run(BIBO bibo, String[] args) {
        return new GPTool().run(bibo, args);
    }
}
