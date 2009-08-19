/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Hendrik Tews, tews@cs.ru.nl
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

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import net.sourceforge.gpj.cardservices.exceptions.CipherException;

/**
 * This is the BouncyCastle implementation of AbstractCipher
 * 
 * @author F. Kooman <F.Kooman@student.science.ru.nl>
 * 
 */
public class BouncyCipher extends AbstractCipher {

    private BufferedBlockCipher cipher;

    BouncyCipher() {
        super();
    }

    BouncyCipher(int alg) throws CipherException {
        super(alg);
    }

    BouncyCipher(int alg, byte[] key) throws CipherException {
        super(alg, key);
    }

    BouncyCipher(int alg, byte[] key, byte[] iv) throws CipherException {
        super(alg, key, iv);
    }

    public byte[] encryptImpl(byte[] enc, int offset, int length)
            throws CipherException {
        try {
            /* See http://java.sun.com/developer/J2METechTips/2001/tt1217.html */
            int size = cipher.getOutputSize(length);
            byte[] result = new byte[size];
            int olen = cipher.processBytes(enc, offset, length, result, 0);
            olen += cipher.doFinal(result, olen);

            if (olen < size) {
                byte[] tmp = new byte[olen];
                System.arraycopy(result, 0, tmp, 0, olen);
                result = tmp;
            }
            return result;
        } catch (Exception e) {
            throw new CipherException("Encryption error");
        }
    }

    public void initCipherImpl() throws CipherException {
        try {
            switch (alg) {
            case DESEDE_CBC_NOPADDING:
                cipher = new BufferedBlockCipher(new CBCBlockCipher(
                        new DESedeEngine()));
                break;
            case DESEDE_ECB_NOPADDING:
                cipher = new BufferedBlockCipher(new DESedeEngine());
                break;
            case DES_CBC_NOPADDING:
                cipher = new BufferedBlockCipher(new CBCBlockCipher(
                        new DESEngine()));
                break;
            case DES_ECB_NOPADDING:
                cipher = new BufferedBlockCipher(new DESEngine());
                break;
            default:
                throw new CipherException("Algorithm not implemented (yet)");
            }
        } catch (Exception e) {
            throw new CipherException("Cipher Initialization Error");
        }
    }

    protected void initParametersImpl() throws CipherException {
        try {
            if (iv != null) {
                cipher.init(true, new ParametersWithIV(new KeyParameter(key),
                        iv));
            } else {
                cipher.init(true, new KeyParameter(key));
            }
        } catch (Exception e) {
            throw new CipherException("Parameters Initialization Error");
        }
    }

}
