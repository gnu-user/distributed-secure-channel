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

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.jgroups.Address;
import org.jgroups.Message;
import org.jgroups.ReceiverAdapter;

import com.DSC.crypto.Cipher;
import com.DSC.crypto.ECDSA;
import com.DSC.crypto.ECGKeyUtil;
import com.DSC.message.AuthAcknowledge;
import com.DSC.message.AuthRequest;
import com.DSC.message.EncryptedMessage;
import com.DSC.message.Key;
import com.DSC.message.SecureMessage;
import com.DSC.utility.ProgramState;

public class ReceiveController extends ReceiverAdapter
{
    /**
     * 
     * @param msg
     */
    @Override
    public void receive(Message msg)
    {
        /* Ignore any messages from blocked senders */
        System.out.println(msg.getSrc());
        if (ProgramState.blacklist.contains(msg.getSrc()))
        {
            System.out.println("BANNED: " + msg.getSrc());
            return;
        }
        
        /* Attempt to cast the message type and call the appropriate handler */
        try
        {
            SecureMessage secureMsg = (SecureMessage)msg.getObject();
        
            switch (secureMsg.getType())
            {
                case AUTH_REQUEST:
                    authRequestHandler(secureMsg, msg.getSrc());
                    break;
                case AUTH_ACKNOWLEDGE:
                    authAcknowledgeHandler(secureMsg);
                    break;
                case KEY_EXCHANGE:
                    keyExchangeHandler(secureMsg);
                    break;
                case KEY:
                    keyHandler(secureMsg);
                    break;
                case ENCRYPTED_MESSAGE:
                    encryptedMessageHandler(secureMsg);
                    break;
                default:
                    throw new IllegalArgumentException("Invalid message type!");
            }
        }
        catch (ClassCastException ce)
        {
            System.err.println("Invalid message object for type provided!");
            ce.printStackTrace();
        }
        catch (InvalidCipherTextException cte)
        {
            cte.printStackTrace();
        }
        catch (Exception e)
        {
            System.err.println("Something went terribly wrong!");
            e.printStackTrace();
        }
    }

    /**
     * 
     * @param msg
     */
    private void authRequestHandler(SecureMessage msg, Address src)
    {
        // Check state
            // If authenticated state
                // Prompt user to authenticate
        System.out.println("AUTHENTICATION REQUEST RECEIVED!");
        System.out.println(ProgramState.passphrase);
        
        AuthRequest authRequest = (AuthRequest) msg;
        System.out.println(authRequest.getPublicKey().toString());
        System.out.println(authRequest.getSignature().toString());
        
        if (ECDSA.verifyAuthRequest(ECGKeyUtil.decodePubKey(authRequest.getPublicKey()), 
                ProgramState.passphrase, authRequest.getSignature()))
        {
            System.out.println("VALID");
        }
        else
        {
            System.out.println("INVALID");
            ProgramState.blacklist.add(src);
        }
        
        
        // Send acknowledge if valid
        // ban if reject
        // do nothing if ignore
        
    }

    /**
     * 
     * @param msg
     */
    private void authAcknowledgeHandler(SecureMessage msg)
    {
        System.out.println("AUTHENTICATION ACKNOWLEDGE RECEIVED!");
        
        // Check if in requesting auth state
        if (! ProgramState.AUTHENTICATION_REQUEST)
        {
            return;
        }
        
        AuthAcknowledge authAcknowledge = (AuthAcknowledge) msg;
        System.out.println(new String(Hex.encode(authAcknowledge.getPublicKey())));
        System.out.println(new String(Hex.encode(authAcknowledge.getAuthKey())));
        System.out.println(authAcknowledge.getSignature()[0]);
        System.out.println(authAcknowledge.getSignature()[1]);
        
        ECPublicKeyParameters pubKey = ECGKeyUtil.decodePubKey(authAcknowledge.getPublicKey());
        ECPublicKeyParameters authKey = ECGKeyUtil.decodePubKey(authAcknowledge.getAuthKey());
        
        // Check if acknowledge valid
        if (ECDSA.verifyAuthAcknowledge(pubKey, authKey, ProgramState.passphrase, authAcknowledge.getSignature()))
        {
            // Add the node that acknowledged as trusted (for client requesting access)
            if (! ProgramState.trustedKeys.contains(pubKey))
            {
                ProgramState.trustedKeys.add(pubKey);
            }
        }
    }

    /**
     * 
     * @param msg
     */
    private void keyExchangeHandler(SecureMessage msg)
    {
        // Check state, if awaiting key request
            // Check key received is from trusted
            // Check key received is valid
        
        // Back-off timer
            // If key already sent by someone else, stop
    }

    /**
     * 
     * @param msg
     */
    private void keyHandler(SecureMessage msg)
    {
        System.out.println("KEY RECEIVED!");
        
        // Check state, if awaiting key exchange
        if (! ProgramState.KEY_EXCHANGE_REQUEST)
        {
            return;
        }
        
        Key key = (Key) msg;
        System.out.println(new String(Hex.encode(key.getPublicKey())));
        System.out.println(new String(Hex.encode(key.getSymmetricKey())));
        System.out.println(key.getSignature()[0]);
        System.out.println(key.getSignature()[1]);
        
        ECPublicKeyParameters pubKey = ECGKeyUtil.decodePubKey(key.getPublicKey());
        
        // If from trusted contact
        if (ProgramState.trustedKeys.contains(pubKey))
        {
            // Verify key
            if (ECDSA.verifyKey(pubKey, key.getSymmetricKey(), ProgramState.passphrase, key.getSignature()))
            {
                // Set symmetric key
                // update state to not receiving
                ProgramState.symmetricKey = key.getSymmetricKey();
                ProgramState.KEY_EXCHANGE_REQUEST = true;
            }
        }
    }

    /**
     * 
     * @param msg
     */
    private void encryptedMessageHandler(SecureMessage msg) 
            throws InvalidCipherTextException
    {
        /* Check that in a valid state */
        if (! ProgramState.AUTHENTICATED)
        {
            return;
        }
        
        System.out.println("ENCRYPTED MESSAGE RECEIVED");
        
        EncryptedMessage encryptedMessage = (EncryptedMessage) msg;
        System.out.println(new String(Hex.encode(encryptedMessage.getIV())));
        System.out.println(new String(Hex.encode(encryptedMessage.getMessage())));
        System.out.println(new String(Hex.encode(encryptedMessage.getHMAC()[0].toByteArray())));
        
        
        /* Display the decrypted message */
        
        if (Cipher.verifyHMAC(ProgramState.passphrase, encryptedMessage.getHMAC(), 
                encryptedMessage.getMessage()))
        {            
            /* Display the decrypted message */
            byte[] message = Cipher.decryptMsg(
                    ProgramState.symmetricKey, 
                    encryptedMessage.getIV(), 
                    encryptedMessage.getMessage());
            
            System.out.println("> " + new String(message));
        }
    }
}