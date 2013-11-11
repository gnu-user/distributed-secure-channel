package com.DSC.crypto;

import java.math.BigInteger;
import java.sql.Timestamp;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

public abstract class ECDSA
{
    private static final ECKeyParam param = new ECKeyParam();
    
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
        byte[] _pubKey = ECGKeyUtil.encodePubKey(param, pubKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and passphrase */
        byte[] data = new byte[_pubKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length, _passphrase.length);
        
        return sign(priKey, data);
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
        byte[] _pubKey = ECGKeyUtil.encodePubKey(param, pubKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and passphrase */
        byte[] data = new byte[_pubKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length, _passphrase.length);
        
        return verify(pubKey, data, signature);
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
        byte[] _pubKey = ECGKeyUtil.encodePubKey(param, pubKey);
        byte[] _authKey = ECGKeyUtil.encodePubKey(param, authKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and passphrase */
        byte[] data = new byte[_pubKey.length + _authKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(_authKey, 0, data, _pubKey.length, _authKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length + _authKey.length, _passphrase.length);
        
        return sign(priKey, data);

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
        byte[] _pubKey = ECGKeyUtil.encodePubKey(param, pubKey);
        byte[] _authKey = ECGKeyUtil.encodePubKey(param, authKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and byte arrays */
        byte[] data = new byte[_pubKey.length + _authKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(_authKey, 0, data, _pubKey.length, _authKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length + _authKey.length, _passphrase.length);
        
        return verify(pubKey, data, signature);
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
        byte[] _pubKey = ECGKeyUtil.encodePubKey(param, pubKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and byte arrays */
        byte[] data = new byte[_pubKey.length + symmetricKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(symmetricKey, 0, data, _pubKey.length, symmetricKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length + symmetricKey.length, _passphrase.length);
        
        return sign(priKey, data);        
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
        byte[] _pubKey = ECGKeyUtil.encodePubKey(param, pubKey);
        byte[] _passphrase = passphrase.getBytes();
        
        /* Combine the public key and byte arrays */
        byte[] data = new byte[_pubKey.length + symmetricKey.length + _passphrase.length];
        System.arraycopy(_pubKey, 0, data, 0, _pubKey.length);
        System.arraycopy(symmetricKey, 0, data, _pubKey.length, symmetricKey.length);
        System.arraycopy(_passphrase, 0, data, _pubKey.length + symmetricKey.length, _passphrase.length);
        
        return verify(pubKey, data, signature); 
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
