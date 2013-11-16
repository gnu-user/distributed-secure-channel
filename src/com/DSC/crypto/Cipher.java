/**
 * Distributed Secure Channel
 * A novel distributed cryptosystem based on the concepts of PGP and Bitcoin.
 *
 * Copyright (C) 2013, Jonathan Gillett, Joseph Heron, and Daniel Smullen
 * All rights reserved.
 *
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.DSC.crypto;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.Grain128Engine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.IESParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public abstract class Cipher
{
    /**
     * 
     * @param priKey
     * @param pubKey
     * @param passphrase
     * @param data
     * @return
     * @throws InvalidCipherTextException
     */
    public static byte[] encryptKey(CipherParameters priKey, CipherParameters pubKey, 
            String passphrase, byte[] data) throws InvalidCipherTextException
    {
        /* Initialize IESEngine in stream mode */
        IESEngine engine = new IESEngine(
                                    new ECDHCBasicAgreement(),
                                    new KDF2BytesGenerator(new SHA256Digest()),
                                    new HMac(new SHA256Digest()));
        
        /* Set the IESEngine cipher parameters as the passphrase and passphrase reversed */
        IESParameters param = new IESParameters(
                                    passphrase.getBytes(), 
                                    new StringBuilder(passphrase).reverse().toString().getBytes(),
                                    engine.getMac().getMacSize() * 8);
        
        /* Initialize the engine and encrypt the key */
        engine.init(true, priKey, pubKey, param);
        return engine.processBlock(data, 0, data.length);
    }
    
    /**
     * 
     * @param priKey
     * @param pubKey
     * @param passphrase
     * @param data
     * @return
     * @throws InvalidCipherTextException
     */
    public static byte[] decryptKey(CipherParameters priKey, CipherParameters pubKey, 
            String passphrase, byte[] data) throws InvalidCipherTextException
    {
        /* IESEngine in stream mode */
        IESEngine engine = new IESEngine(
                                    new ECDHCBasicAgreement(),
                                    new KDF2BytesGenerator(new SHA256Digest()),
                                    new HMac(new SHA256Digest()));
        
        /* Set the IESEngine cipher parameters as the passphrase and passphrase reversed */
        IESParameters param = new IESParameters(
                                    passphrase.getBytes(), 
                                    new StringBuilder(passphrase).reverse().toString().getBytes(),
                                    engine.getMac().getMacSize() * 8);
        
        /* Initialize the engine and decrypt the key */
        engine.init(false, priKey, pubKey, param);
        return engine.processBlock(data, 0, data.length);
    }
    
    /**
     * 
     * @param symmetricKey
     * @param IV
     * @return
     */
    public static byte[] encryptMsg(byte[] symmetricKey, byte[] IV, byte[] data)
    {
        byte[] cipherText = new byte[data.length];
        
        /* Grain stream cipher */
        StreamCipher grain = new Grain128Engine();
        
        /* Initialize stream cipher */
        ParametersWithIV param = new ParametersWithIV(new KeyParameter(symmetricKey), IV);
        grain.init(true, param);
        
        /* Encrypt the message */
        grain.processBytes(data, 0, data.length, cipherText, 0);
        return cipherText;
    }
    
    /**
     * 
     * @param symmetricKey
     * @param IV
     * @return
     */
    public static byte[] decrypttMsg(byte[] symmetricKey, byte[] IV, byte[] data)
    {
        byte[] cipherText = new byte[data.length];
        
        /* Grain stream cipher */
        StreamCipher grain = new Grain128Engine();
        
        /* Initialize stream cipher */
        ParametersWithIV param = new ParametersWithIV(new KeyParameter(symmetricKey), IV);
        grain.init(false, param);
        
        /* Decrypt the message */
        grain.processBytes(data, 0, data.length, cipherText, 0);
        return cipherText;
    }
}
