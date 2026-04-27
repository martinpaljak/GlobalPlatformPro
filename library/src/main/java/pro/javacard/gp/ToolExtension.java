// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: LGPL-3.0-or-later

package pro.javacard.gp;

// ServiceLoader SPI for next-gen tool (JDK 21+)
public interface ToolExtension {
    int run(String[] args);
}
