/** 
 * Copyright (C) 2013 Jonathan Gillett
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

import com.google.common.io.BaseEncoding;

import java.math.BigInteger;
import java.security.InvalidParameterException;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * A helpful key utility class which contains utility operations which are used
 * when performing an Elliptic Curve Gillett (ECG) Exchange.
 * 
 * It provide key exchange utility operations for encoding and decoding Elliptic
 * Curve keys.
 */
public abstract class ECGKeyUtil
{
    private static final ECKeyParam param = new ECKeyParam();
    
    /**
     * encodePubKey A function which takes an ECC public key parameter object
     * and returns the ASN.1 encoded X and Y values for the public key Q.
     * 
     * @param param The Elliptic Curve key parameter which contains the curve
     * specifications and domain parameters
     * @param pubKey an ECC public key parameter which implements CipherParameters
     * @return A byte array of the ASN.1 encoded public key Q
     */
    static public byte[] encodePubKey(CipherParameters pubKey)
    		throws InvalidParameterException
    {
    	if (pubKey instanceof ECPublicKeyParameters)
    	{
    		/*
    		 * This statement does the following:
    		 *     
    		 *     1. It takes the X and Y value of the public key Q
    		 *     2. Then creates a single encoded byte array for the public key Q
    		 *     3. Finally it creates a hex encoded byte array (ASN.1) of the encoded public key Q
    		 */
    		return param.getCurve().createPoint(
    					((ECPublicKeyParameters)pubKey).getQ().getX().toBigInteger(), 	// X
    					((ECPublicKeyParameters)pubKey).getQ().getY().toBigInteger(), 	// Y
    					true) 															// Use Compression
					.getEncoded();	// Encoded public key Q
    	}
    	else
    	{
    		throw new InvalidParameterException("The public key provided is not an ECPublicKeyParameters");
    	}
    }
    
    
    /**
     * encodeBase64PubKey A wrapper function for encodePubKey() which takes an ECC 
     * public key parameter object and returns the ASN.1 encoded X and Y values
     * for the public key Q that is then encoded in base64 encoding for proper
     * storage and transmission in textual form.
     * 
     * This may be needed to transmit/store the ASN.1 encoded public key properly.
     * 
     * @param param The Elliptic Curve key parameter which contains the curve
     * specifications and domain parameters
     * @param pubKey an ECC public key parameter which implements CipherParameters
     * @return The ASN.1 encoded public key Q as a BASE64 encoded as a String
     */
    static public String encodeBase64PubKey(CipherParameters pubKey)
    		throws InvalidParameterException
    {
    	return BaseEncoding.base64().encode(encodePubKey(pubKey));
    }
    
    
    /**
     * encodePriKey A function which takes an ECC private key parameter object
     * and returns the private key D BigInteger value as a byte array
     * 
     * @param param The Elliptic Curve key parameter which contains the curve
     * specifications and domain parameters
     * @param priKey an ECC private key parameter object which implements CipherParameters
     * @return A byte array of the private key D BigInteger value
     * @throws InvalidParameterException
     */
    static public byte[] encodePriKey(CipherParameters priKey)
    		throws InvalidParameterException
	{
    	if (priKey instanceof ECPrivateKeyParameters)
    	{
    		/* Return the private key D BigInteger value as byte array */
    		return ((ECPrivateKeyParameters) priKey).getD().toByteArray();
    	}
    	else
    	{
    		throw new InvalidParameterException("The private key provided is not an ECPrivateKeyParameters");
    	}
	}
    
    
    /**
     * encodeBase64PriKey A wrapper function which takes an ECC private key parameter
     * object and returns the private key D BigInteger value that is encoded as base64
     * for proper storage and transmission in textual form.
     * 
     * @param param The Elliptic Curve key parameter which contains the curve
     * specifications and domain parameters
     * @param priKey an ECC private key parameter object which implements CipherParameters
     * @return The base64 encoded private key D BigInteger value
     * @throws InvalidParameterException
     */
    static public String encodeBase64PriKey(CipherParameters priKey)
    		throws InvalidParameterException
	{
    		/* Return the private key D BigInteger value encoded as base64 */
    		return BaseEncoding.base64().encode(
    				encodePriKey(priKey));
	}
    
    
    /**
     * decodePubKey A function which takes an ASN.1 encoded ECC public key Q
     * and returns an ECPublicKeyParameters object for the public key Q. 
     * 
     * @param param The Elliptic Curve key parameter which contains the curve
     * specifications and domain parameters
     * @param encodedPubkey A byte array of the ASN.1 encoded public key Q
     * @return An ECC public key parameter for Q, ECPublicKeyParametersimplements
     */
    static public ECPublicKeyParameters decodePubKey(byte[] encodedPubKey)
    {
		/*
		 * Takes the encoded public key Q and decodes an X and Y value for 
		 * the point Q, then returns an ECPublicKeyParameters object for
		 * the elliptic curve parameters specified 
		 */
    	return new ECPublicKeyParameters(
    			param.getCurve().decodePoint(encodedPubKey), 	// Q
    			param.getECDomainParam());
    }
    
    
    /**
     * decodeBase64PubKey A wrapper function for decodePubKey which takes an 
     * ASN.1 encoded ECC public key Q that was then encoded as base64
     * and returns an ECPublicKeyParameters object for the public key Q. 
     * 
     * @param param The Elliptic Curve key parameter which contains the curve
     * specifications and domain parameters
     * @param encodedPubkey A byte array of the ASN.1 encoded public key Q
     * @return An ECC public key parameter for Q, ECPublicKeyParametersimplements
     */
    static public ECPublicKeyParameters decodeBase64PubKey(	ECKeyParam param, 
    														String encodedPubKey)
    {
    	return decodePubKey(BaseEncoding.base64().decode(encodedPubKey));
    }
    
    
    /**
     * decodeSignedPubKey A function which takes an ASN.1 encoded ECC public key Q
     * that is signed using the Elliptic Curve Gillett (ECG) Exchange key exchange
     * and returns an ECPublicKeyParameters object for the public key Q.
     * 
     * @param param The Elliptic Curve key parameter which contains the curve
     * specifications and domain parameters
     * @param digest The digest function used to originally sign the key such as SHA256
     * @param signedPubkey A byte array of the ASN.1 encoded public key Q that is signed
     * @return An ECC public key parameter for Q, ECPublicKeyParametersimplements
     */
    static public ECPublicKeyParameters decodeSignedPubKey(Digest digest, 
													       byte[] signedPubKey)
    {
    	/*
    	 * Retrieve the ASN.1 encoded ECC public key Q from the contents of signed public key  
    	 */
    	byte[] encodedPubKey = new byte[signedPubKey.length - digest.getDigestSize()];
    	System.arraycopy(signedPubKey, 0, encodedPubKey, 0, signedPubKey.length - digest.getDigestSize());
    	
		/*
		 * Takes the encoded public key Q and decodes an X and Y value for 
		 * the point Q, then returns an ECPublicKeyParameters object for
		 * the elliptic curve parameters specified 
		 */
    	
    	return new ECPublicKeyParameters(
    			param.getCurve().decodePoint(encodedPubKey), 	// Q
    			param.getECDomainParam());
    }
    
    
    /**
     * decodeBase64SignedPubKey A wrapper function for decodeSignedPubKey which 
     * takes an ASN.1 encoded ECC public key Q that is signed using the Elliptic
     * Curve Gillett (ECG) Exchange key exchange and that was then encoded as base64
     * and returns an ECPublicKeyParameters object for the public key Q.
     * 
     * @param param The Elliptic Curve key parameter which contains the curve
     * specifications and domain parameters
     * @param digest The digest function used to originally sign the key such as SHA256
     * @param signedPubkey A byte array of the ASN.1 encoded public key Q, encoded as
     * BASE64, that is signed
     * @return An ECC public key parameter for Q, ECPublicKeyParametersimplements
     */
    static public ECPublicKeyParameters decodeBase64SignedPubKey(Digest digest, 
														         String signedPubKey)
    {
    	return decodeSignedPubKey(digest, BaseEncoding.base64().decode(signedPubKey));
    	
    }
   
    
    /**
     * decodePriKey A function which takes an ECC private key parameter object and 
     * returns an ECPrivateKeyParameters object for the private key D BigInteger 
     * value.
     * 
     * @param param The Elliptic Curve key parameter which contains the curve
     * specifications and domain parameters
     * @param priKey a byte array of the private key D BigInteger value
     * @return an ECPrivateKeyParameters object for the private key D BigInteger value
     */
    static public ECPrivateKeyParameters decodePriKey(byte[] encodedPriKey)
    {
    	return new ECPrivateKeyParameters(
    			new BigInteger(encodedPriKey),		// D
    			param.getECDomainParam());
    }
    
    
    /**
     * decodeBase64PriKey A function wrapper function for decodePriKey which takes
     * a base64 encoded ECC private key parameter object and returns an 
     * ECPrivateKeyParameters object for the private key D BigInteger value.
     * 
     * @param param The Elliptic Curve key parameter which contains the curve
     * specifications and domain parameters
     * @param priKey a base64 encoded byte array of the private key D BigInteger value
     * @return an ECPrivateKeyParameters object for the private key D BigInteger value
     */
    static public ECPrivateKeyParameters decodeBase64PriKey(String encodedPriKey)
    {
    	return decodePriKey(BaseEncoding.base64().decode(encodedPriKey));
    }
}