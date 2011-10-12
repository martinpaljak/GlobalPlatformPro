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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import net.sourceforge.gpj.cardservices.exceptions.CipherException;

/**
 * JavaCrypto is a wrapper for using the Java SDK javax.crypto.* system.
 * 
 * This is the javax.crypto.Cipher implementation of AbstractCipher
 * 
 * @author F. Kooman <F.Kooman@student.science.ru.nl>
 * 
 */
public class JavaCipher extends AbstractCipher implements ICipher {

    private Cipher cipher;

    JavaCipher() {
        super();
    }

    JavaCipher(int alg) throws CipherException {
        super(alg);
    }

    JavaCipher(int alg, byte[] key) throws CipherException {
        super(alg, key);
    }

    JavaCipher(int alg, byte[] key, byte[] iv) throws CipherException {
        super(alg, key, iv);
    }

    public byte[] encryptImpl(byte[] enc, int offset, int length)
            throws CipherException {
        try {
            return cipher.doFinal(enc, offset, length);
        } catch (Exception e) {
            throw new CipherException("Encryption error");
        }
    }

    public void initCipherImpl() throws CipherException {
        try {
            switch (alg) {
            case DESEDE_CBC_NOPADDING:
                cipher = Cipher.getInstance("DESede/CBC/NoPadding");
                break;
            case DESEDE_ECB_NOPADDING:
                cipher = Cipher.getInstance("DESede/ECB/NoPadding");
                break;
            case DES_CBC_NOPADDING:
                cipher = Cipher.getInstance("DES/CBC/NoPadding");
                break;
            case DES_ECB_NOPADDING:
                cipher = Cipher.getInstance("DES/ECB/NoPadding");
                break;
            default:
                throw new CipherException("Algorithm not implemented yet");
            }
        } catch (Exception e) {
            throw new CipherException("Crypto engine Initialization Error");
        }
    }

    protected void initParametersImpl() throws CipherException {
        try {
            /* SecretKeySpec needs an algorithm passed as string parameter */
            String keytype = (key.length == 24) ? "DESede" : "DES";
            if (iv != null)
                cipher.init(Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(key, keytype),
                        new IvParameterSpec(iv));
            else
                cipher.init(Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(key, keytype));
        } catch (Exception e) {
            throw new CipherException("Parameters initialization error");
        }
    }
}
