/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
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

package net.sourceforge.gpj.cardservices.ciphers;

import net.sourceforge.gpj.cardservices.exceptions.CipherException;

/**
 * Interface file for custom Ciphers
 * 
 * @author F. Kooman <F.Kooman@student.science.ru.nl>
 * 
 */
public interface ICipher {

    public final static int DESEDE_CBC_NOPADDING = 1;

    public final static int DESEDE_ECB_NOPADDING = 2;

    public final static int DES_CBC_NOPADDING = 3;

    public final static int DES_ECB_NOPADDING = 4;

    public void setAlgorithm(int alg) throws CipherException;

    public void setIV(byte[] iv) throws CipherException;

    public void setKey(byte[] key) throws CipherException;

    public byte[] encrypt(byte[] enc) throws CipherException;

    public byte[] encrypt(byte[] enc, int offset, int length)
            throws CipherException;

    public class Factory {
        public static ICipher getImplementation() {
            return new JavaCipher();
        }

        public static ICipher getImplementation(int alg) throws CipherException {
            return new JavaCipher(alg);
        }

        public static ICipher getImplementation(int alg, byte[] key)
                throws CipherException {
            return new JavaCipher(alg, key);
        }

        public static ICipher getImplementation(int alg, byte[] key, byte[] iv)
                throws CipherException {
            return new JavaCipher(alg, key, iv);
        }

    }

}
