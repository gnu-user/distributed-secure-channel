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

import java.math.BigInteger;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.Digest;

public abstract class ECDSA
{    
    /**
     * Signs the public key for an authentication request and returns the signature
     * @param priKey The private key used to sign the data
     * @param pubKey The public key to be signed for the authentication request
     * @param passphrase The passphrase used to sign the key for the authentication request
     * @return The signature of the public key authentication request
     */
    public static BigInteger[] signAuthRequest(CipherParameters priKey, CipherParameters pubKey, 
            String passphrase)
    {   
        /* Convert the public key and passphrase to byte arrays */
        byte[] _pubKey = ECGKeyUtil.encodePubKey(pubKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and passphrase */
        byte[] data = new byte[_pubKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length, _passphrase.length);
        
        return sign(priKey, hash(data));
    }
    
    
    /**
     * 
     * @param pubKey
     * @param passphrase
     * @param signature
     * @return
     */
    public static boolean verifyAuthRequest(CipherParameters pubKey, String passphrase, 
            BigInteger[] signature)
    {   
        /* Convert the public key and passphrase to byte arrays */
        byte[] _pubKey = ECGKeyUtil.encodePubKey(pubKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and passphrase */
        byte[] data = new byte[_pubKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length, _passphrase.length);
        
        return verify(pubKey, hash(data), signature);
    }
    
    
    /**
     * Signs the data for an authentication acknowledge and returns the signature
     * @param priKey The private key used to sign the data
     * @param pubKey The public key of the client signing the data
     * @param authKey The authenticated public key
     * @param passphrase The passphrase used to sign the authentication acknowledge
     * @return The signature of the public key authentication request
     */
    public static BigInteger[] signAuthAcknowledge(CipherParameters priKey, CipherParameters pubKey, 
            CipherParameters authKey, String passphrase)
    {
        /* Convert the data to byte arrays */
        byte[] _pubKey = ECGKeyUtil.encodePubKey(pubKey);
        byte[] _authKey = ECGKeyUtil.encodePubKey(authKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and passphrase */
        byte[] data = new byte[_pubKey.length + _authKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(_authKey, 0, data, _pubKey.length, _authKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length + _authKey.length, _passphrase.length);
        
        return sign(priKey, hash(data));
    }
    
    
    /**
     * Verify the data for an authentication acknowledge and returns true/fals
     * @param pubKey The public key of the client that signed data
     * @param authKey The authenticated public key
     * @param passphrase The passphrase used to sign the authentication acknowledge
     * @return The signature of the public key authentication request
     */
    public static boolean verifyAuthAcknowledge(CipherParameters pubKey, CipherParameters authKey, 
            String passphrase, BigInteger[] signature)
    {
        /* Convert the data to byte arrays */
        byte[] _pubKey = ECGKeyUtil.encodePubKey(pubKey);
        byte[] _authKey = ECGKeyUtil.encodePubKey(authKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and byte arrays */
        byte[] data = new byte[_pubKey.length + _authKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(_authKey, 0, data, _pubKey.length, _authKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length + _authKey.length, _passphrase.length);
        
        return verify(pubKey, hash(data), signature);
    }
    
    
    /**
     * Signs the public key for a key exchange and returns the signature
     * @param priKey The private key used to sign the data
     * @param pubKey The public key to be signed for the authentication request
     * @param passphrase The passphrase used to sign the key for the authentication request
     * @return The signature of the public key authentication request
     */
    public static BigInteger[] signKeyExchange(CipherParameters priKey, CipherParameters pubKey, 
            String passphrase)
    {
        return signAuthRequest(priKey, pubKey, passphrase);
    }
    
    
    /**
     * 
     * @param pubKey
     * @param passphrase
     * @param signature
     * @return
     */
    public static boolean verifyKeyExchange(CipherParameters pubKey, String passphrase, 
            BigInteger[] signature)
    {
        return verifyAuthRequest(pubKey, passphrase, signature);
    }
    
    
    /**
     * 
     * @param priKey
     * @param pubKey
     * @param symmetricKey The ENCRYPTED symmetric key
     * @param passphrase
     * @return
     */
    public static BigInteger[] signKey(CipherParameters priKey, CipherParameters pubKey, 
            byte[] symmetricKey, String passphrase)
    {
        /* Convert the data to byte arrays */
        byte[] _pubKey = ECGKeyUtil.encodePubKey(pubKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and byte arrays */
        byte[] data = new byte[_pubKey.length + symmetricKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(symmetricKey, 0, data, _pubKey.length, symmetricKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length + symmetricKey.length, _passphrase.length);
        
        return sign(priKey, hash(data));        
    }
    
    
    /**
     * 
     * @param pubKey
     * @param symmetricKey
     * @param passphrase
     * @param signature
     * @return
     */
    public static boolean verifyKey(CipherParameters pubKey, byte[] symmetricKey, 
            String passphrase, BigInteger[] signature)
    {
        /* Convert the data to byte arrays */
        byte[] _pubKey = ECGKeyUtil.encodePubKey(pubKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and byte arrays */
        byte[] data = new byte[_pubKey.length + symmetricKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(symmetricKey, 0, data, _pubKey.length, symmetricKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length + symmetricKey.length, _passphrase.length);
        
        return verify(pubKey, hash(data), signature); 
    }
    
    
    /**
     * 
     * @param data
     * @return
     */
    private static byte[] hash(byte[] data)
    {
        Digest digest = new SHA256Digest();
        byte[] hash = new byte[digest.getDigestSize()];
        
        digest.update(data, 0, data.length);
        digest.doFinal(hash, 0);
        digest.reset();
        
        return hash;
    }
    
    
    /**
     * Sign the data, return the signature
     * @param priKey
     * @param data
     * @return
     */
    private static BigInteger[] sign(CipherParameters priKey, byte[] data)
    {
        ECDSASigner ecdsa = new ECDSASigner();
        ecdsa.init(true, priKey);
        return ecdsa.generateSignature(data);
    }
    
    
    /**
     * Verify the data, return true if the signature is valid, false otherwise
     * @param pubKey
     * @param data
     * @param signature
     * @return
     */
    private static boolean verify(CipherParameters pubKey, byte[] data, BigInteger[] signature)
    {
        ECDSASigner ecdsa = new ECDSASigner();
        ecdsa.init(false, pubKey);
        return ecdsa.verifySignature(data, signature[0], signature[1]);
    }
}
