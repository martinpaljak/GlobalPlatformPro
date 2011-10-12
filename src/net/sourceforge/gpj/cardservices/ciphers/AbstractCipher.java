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

public abstract class AbstractCipher implements ICipher {

    protected byte[] key;

    protected byte[] iv;

    protected int alg;

    AbstractCipher() {
        key = null;
        iv = null;
        alg = 0;
    }

    AbstractCipher(int alg) throws CipherException {
        setAlgorithm(alg);
        key = null;
        iv = null;
    }

    AbstractCipher(int alg, byte[] key) throws CipherException {
        setAlgorithm(alg);
        setKey(key);
        iv = null;
    }

    AbstractCipher(int alg, byte[] key, byte[] iv) throws CipherException {
        setAlgorithm(alg);
        setKey(key);
        setIV(iv);
    }

    protected void initCipher() throws CipherException {
        initCipherImpl();
    }

    protected abstract void initCipherImpl() throws CipherException;

    protected void initParameters() throws CipherException {
        if (alg == 0) {
            throw new CipherException("Cipher not initialized");
        }
        if (key.length != 8 && key.length != 24) {
            throw new CipherException("Wrong key length");
        }
        initParametersImpl();
    }

    public byte[] encrypt(byte[] enc) throws CipherException {
        return encrypt(enc, 0, enc.length);
    }

    public byte[] encrypt(byte[] enc, int offset, int length)
            throws CipherException {
        if (alg == 0) {
            throw new CipherException("Cipher not initialized");
        }
        if (key == null) {
            throw new CipherException("Key not initialized");
        }
        return encryptImpl(enc, offset, length);
    }

    protected abstract byte[] encryptImpl(byte[] enc, int offset, int length)
            throws CipherException;

    protected abstract void initParametersImpl() throws CipherException;

    public void setAlgorithm(int alg) throws CipherException {
        this.alg = alg;
        initCipher();
    }

    public void setIV(byte[] iv) throws CipherException {
        if (iv == null || iv.length == 0) {
            throw new CipherException("Invalid IV length");
        }
        this.iv = new byte[iv.length];
        System.arraycopy(iv, 0, this.iv, 0, iv.length);
        if (alg != 0) {
            initParameters();
        }
    }

    public void setKey(byte[] key) throws CipherException {
        if (key == null || key.length == 0) {
            throw new CipherException("Invalid key length");
        }
        this.key = new byte[key.length];
        System.arraycopy(key, 0, this.key, 0, key.length);
        if (alg != 0) {
            initParameters();
        }
    }
}
