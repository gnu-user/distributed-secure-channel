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
package com.DSC.controller;

import java.math.BigInteger;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.jgroups.Address;
import org.jgroups.Message;

import com.DSC.crypto.Cipher;
import com.DSC.crypto.ECDSA;
import com.DSC.crypto.ECGKeyUtil;
import com.DSC.message.AbstractMessageFactory;
import com.DSC.message.MessageType;
import com.DSC.message.SecureMessage;
import com.DSC.utility.ProgramState;

public class SendController
{
    /**
     * 
     * @param type
     * @param msg
     */
    public void send(MessageType type, Object data, Address dest)
    {
        try
        {
            switch (type)
            {
                case AUTH_REQUEST:
                    authRequestHandler();
                    break;
                case AUTH_ACKNOWLEDGE:
                    authAcknowledgeHandler(data);
                    break;
                case KEY_EXCHANGE:
                    keyExchangeHandler();
                    break;
                case KEY:
                    keyHandler(data);
                    break;
                case ENCRYPTED_MESSAGE:
                    encryptedMessageHandler(data);
                    break;
                default:
                    throw new IllegalArgumentException("Invalid message type!");
            }
        }
        catch (ClassCastException ce)
        {
            System.err.println("Invalid data type provided!");
            ce.printStackTrace();
        }
        catch (Exception e)
        {
            System.err.println("Something went terribly wrong!");
            e.printStackTrace();
        }
    }

    /**
     * Handles sending authentication requests 
     * @throws Exception 
     */
    private void authRequestHandler() throws Exception
    {
        /* Generate the signature for the message */
        System.out.println(ProgramState.passphrase);
        
        BigInteger[] signature = ECDSA.signAuthRequest(
                ProgramState.privateKey, 
                ProgramState.publicKey, 
                ProgramState.passphrase);
        
        /* Create an authentication request message */
        SecureMessage secureMsg = AbstractMessageFactory.createMessage(
                MessageType.AUTH_REQUEST, 
                ECGKeyUtil.encodePubKey(ProgramState.publicKey), 
                null, 
                null, 
                signature);  
        
        /* Send the message using JGroups */
        Message msg = new Message(null, null, secureMsg);
        ProgramState.channel.send(msg);
        
        /* Update the program state */
        ProgramState.AUTHENTICATION_REQUEST = true;
    }

    /**
     * 
     * @param authKey
     * @throws Exception 
     */
    private void authAcknowledgeHandler(Object authKey) throws Exception
    {
        /* Generate the signature for the authenticated message */
        BigInteger[] signature = ECDSA.signAuthAcknowledge(
                ProgramState.privateKey, 
                ProgramState.publicKey, 
                (ECPublicKeyParameters) authKey, 
                ProgramState.passphrase);
        
        /* Create an authentication acknowledge message */
        SecureMessage secureMsg = AbstractMessageFactory.createMessage(
                MessageType.AUTH_ACKNOWLEDGE, 
                ECGKeyUtil.encodePubKey(ProgramState.publicKey), 
                null, 
                ECGKeyUtil.encodePubKey((ECPublicKeyParameters) authKey), 
                signature);
        
        /* Send the message using JGroups */
        Message msg = new Message(null, null, secureMsg);
        ProgramState.channel.send(msg);
    }

    /**
     * @throws Exception 
     * 
     */
    private void keyExchangeHandler() throws Exception
    {
        /* Generate the signature for the key exchange message */
        BigInteger[] signature = ECDSA.signKeyExchange(
                ProgramState.privateKey, 
                ProgramState.publicKey, 
                ProgramState.passphrase);
        
        /* Create a key exchange message */
        SecureMessage secureMsg = AbstractMessageFactory.createMessage(
                MessageType.KEY_EXCHANGE, 
                ECGKeyUtil.encodePubKey(ProgramState.publicKey), 
                null,
                null, 
                signature);
        
        /* Send the message using JGroups */
        Message msg = new Message(null, null, secureMsg);
        ProgramState.channel.send(msg);
        
        /* Update the program state */
        ProgramState.KEY_EXCHANGE_REQUEST = true;
    }

    /**
     * 
     * @param authKey
     * @throws InvalidCipherTextException
     * @throws Exception
     */
    private void keyHandler(Object authKey) throws InvalidCipherTextException, Exception
    {
        /* Encrypt the key with the other person's public key */
        byte[] encryptedKey = Cipher.encryptKey(
                ProgramState.privateKey, 
                (ECPublicKeyParameters) authKey, 
                ProgramState.passphrase, 
                ProgramState.symmetricKey);
        
        /* sign the key with my private/public keypair */
        BigInteger[] signature = ECDSA.signKey(
                ProgramState.privateKey, 
                ProgramState.publicKey, 
                encryptedKey,
                ProgramState.passphrase);
        
        /* Send the ENCRYPTED key */
        SecureMessage secureMsg = AbstractMessageFactory.createMessage(
                MessageType.KEY, 
                ECGKeyUtil.encodePubKey(ProgramState.publicKey), 
                null, 
                encryptedKey, 
                signature);
        
        /* Send the message using JGroups */
        Message msg = new Message(null, null, secureMsg);
        ProgramState.channel.send(msg);
    }

    /**
     * 
     * @param msg
     * @throws Exception 
     */
    private void encryptedMessageHandler(Object message) throws Exception
    {
        // Generate another unique IV
        byte[] IV = new byte[12];
        ProgramState.IVEngine.nextBytes(IV);
        
        // Encrypt the message using symmetric key and IV with GRAIN
        byte[] encryptedMessage = Cipher.encryptMsg(
                ProgramState.symmetricKey, 
                IV, 
                ((String) message).getBytes());
        
		// Generate HMAC for the message
        BigInteger[] HMAC = Cipher.generateHMAC(ProgramState.passphrase, encryptedMessage);
        
        //System.out.println("SENDING ENCRYPTED MESSAGE");
        //System.out.println(new String(Hex.encode(encryptedMessage)));
        //System.out.println(new String(Hex.encode(HMAC[0].toByteArray())));
        
		// Send the encrypted message with HMAC
        SecureMessage secureMsg = AbstractMessageFactory.createMessage(
                MessageType.ENCRYPTED_MESSAGE, 
                null, 
                IV, 
                encryptedMessage, 
                HMAC);
        
        /* Send the message using JGroups */
        Message msg = new Message(null, null, secureMsg);
        ProgramState.channel.send(msg);
    }
}