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

import java.io.IOException;

import org.bouncycastle.crypto.CipherParameters;
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
import com.DSC.message.KeyExchange;
import com.DSC.message.MessageType;
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
    private void authRequestHandler(SecureMessage msg, Address src) throws IOException
    {
        System.out.println("AUTHENTICATION REQUEST RECEIVED!");
        
        // Check state
        if (! ProgramState.AUTHENTICATED)
        {
            return;
        }
                
        AuthRequest authRequest = (AuthRequest) msg;
        System.out.println("PUBLIC KEY: " + new String(Hex.encode(authRequest.getPublicKey())));
        //System.out.println(authRequest.getSignature().toString());
        
        ECPublicKeyParameters pubKey = ECGKeyUtil.decodePubKey(authRequest.getPublicKey());
        String strPubKey = new String(Hex.encode(authRequest.getPublicKey()));
        
        // If authenticated state
        // Prompt user to authenticate
        ProgramState.AUTHENTICATION_DECISION = true;
                
        String choice = "";
        
        /*try
        {
            ProgramState.in.close();
            System.out.flush();
            //ProgramState.in = new BufferedReader(new InputStreamReader(System.in));
        }
        catch (IOException io)
        {
            System.out.println("something wrong");
        }*/
        
        
        System.out.println("> Received key exchange from: " + src.toString());
        System.out.println("> Verify/Reject/Ignore (V/R/I): "); 
        //ProgramState.in.mark(0);
        //ProgramState.in.ready();
        //choice = ProgramState.in.readLine().toLowerCase().trim();
        
        
        choice = waitForInput();
        
        System.out.println("GOT IT: " + choice);
        
        if (choice.equalsIgnoreCase("v"))
        {
            if (ECDSA.verifyAuthRequest(pubKey, ProgramState.passphrase, authRequest.getSignature()))
            {
                System.out.println("> Signature valid.");
                System.out.print("> Trust new member? (Y/N): ");
                
                if (waitForInput().equalsIgnoreCase("y"))
                {
                    // Update list of trusted members
                    System.out.println("> Updating list of trusted members...");
                    if (! ProgramState.trustedKeys.contains(strPubKey))
                    {
                        System.out.println("added public key");
                        ProgramState.trustedKeys.add(strPubKey);
                    }
                    
                    // Send authenticated acknowledgement msg
                    System.out.println("> Authenticated member announced.");
                    SendController sendController = new SendController();
                    sendController.send(MessageType.AUTH_ACKNOWLEDGE, pubKey, null);
                    
                    // Update state
                    ProgramState.AUTHENTICATION_DECISION = false;
                    ProgramState.AUTHENTICATION_ACKNOWLEDGE = true;
                }
            }
            else
            {
                System.out.println("> Signature invalid.");
                System.out.print("> Ignore sender? (Y/N): ");
                
                // ban if reject
                if (waitForInput().equalsIgnoreCase("y"))
                {
                    ProgramState.blacklist.add(src);    
                    System.out.println("> Sender ignored permanently.");
                }
                
                //TODO shouldn't you change state?
            }
        }
        //ProgramState.in.reset();
    }
    
    private String waitForInput()
    {
    	while(!ProgramState.symbol.getInputWait() && ProgramState.symbol.getInput() == null)
        {
            synchronized(ProgramState.symbol) {
                try {
                	ProgramState.symbol.wait();
                }
                catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    	ProgramState.symbol.setInputWait();
    	String value = ProgramState.symbol.getInput();
    	ProgramState.symbol.resetInput();
    	
    	return value;
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
            System.out.println("WRONG AUTH ACKNOWLEDGE STATE");
            return;
        }
        
        AuthAcknowledge authAcknowledge = (AuthAcknowledge) msg;
        System.out.println(new String(Hex.encode(authAcknowledge.getPublicKey())));
        System.out.println(new String(Hex.encode(authAcknowledge.getAuthKey())));
        System.out.println(authAcknowledge.getSignature()[0]);
        System.out.println(authAcknowledge.getSignature()[1]);
        
        ECPublicKeyParameters pubKey = ECGKeyUtil.decodePubKey(authAcknowledge.getPublicKey());
        ECPublicKeyParameters authKey = ECGKeyUtil.decodePubKey(authAcknowledge.getAuthKey());
        String strPubKey = new String(Hex.encode(authAcknowledge.getPublicKey()));
        
        // Check if acknowledge valid
        if (ECDSA.verifyAuthAcknowledge(pubKey, authKey, ProgramState.passphrase, authAcknowledge.getSignature()))
        {
            // Add the node that acknowledged as trusted (for client requesting access)
            if (! ProgramState.trustedKeys.contains(strPubKey))
            {
                ProgramState.trustedKeys.add(strPubKey);
            }
            
            ProgramState.AUTHENTICATED = true;
        }
    }

    /**
     * 
     * @param msg
     */
    private void keyExchangeHandler(SecureMessage msg)
    {
        System.out.println("KEY EXCHANGE REQUEST RECEIVED!");
        
        /* Check if awaiting key request state after acknowledgment */
        if (! (ProgramState.AUTHENTICATED && ProgramState.AUTHENTICATION_ACKNOWLEDGE))
        {
            System.out.println("WRONG AUTH KEY EXCHANGE HANDLER STATE");
            return;
        }
        
        KeyExchange keyExchange = (KeyExchange) msg;
        System.out.println("PUBLIC KEY: " + new String(Hex.encode(keyExchange.getPublicKey())));
        System.out.println(keyExchange.getSignature()[0]);
        System.out.println(keyExchange.getSignature()[1]);
        
        ECPublicKeyParameters pubKey = ECGKeyUtil.decodePubKey(keyExchange.getPublicKey());
        String strPubKey = new String(Hex.encode(keyExchange.getPublicKey()));
        
        /* Check if key received is from trusted */
        for (String key : ProgramState.trustedKeys)
        {
            System.out.println(key);
        }
        
        if (! ProgramState.trustedKeys.contains(strPubKey))
        {
            System.out.println("KEY EXCHANGE FROM UNTRUSTED CLIENT!");
            return;
        }
        
        // Check if key received valid
        if (ECDSA.verifyKeyExchange(pubKey, ProgramState.passphrase, keyExchange.getSignature()))
        {
            // Back-off timer
            // If key already sent by someone stop
            // else send the key
            SendController sendController = new SendController();
            sendController.send(MessageType.KEY, pubKey, null);
            
            /* Update the state */
            ProgramState.AUTHENTICATION_ACKNOWLEDGE = false;
        }
    }

    /**
     * 
     * @param msg
     * @throws InvalidCipherTextException 
     */
    private void keyHandler(SecureMessage msg) throws InvalidCipherTextException
    {
        System.out.println("KEY RECEIVED!");
        
        // Check state, if awaiting key exchange
        if (! (ProgramState.AUTHENTICATED && ProgramState.KEY_EXCHANGE_REQUEST))
        {
            return;
        }
        
        Key key = (Key) msg;
        System.out.println(new String(Hex.encode(key.getPublicKey())));
        System.out.println(new String(Hex.encode(key.getSymmetricKey())));
        System.out.println(key.getSignature()[0]);
        System.out.println(key.getSignature()[1]);
        
        ECPublicKeyParameters pubKey = ECGKeyUtil.decodePubKey(key.getPublicKey());
        String strPubKey = new String(Hex.encode(key.getPublicKey()));
        
        // If from trusted contact
        if (ProgramState.trustedKeys.contains(strPubKey))
        {
            // Verify key
            if (ECDSA.verifyKey(pubKey, key.getSymmetricKey(), ProgramState.passphrase, key.getSignature()))
            {
                System.out.println("DECYPTING SYMMETRIC KEY");
                
                /* Decrypt the symmetric key */
                byte[] deccryptedKey = Cipher.decryptKey(
                        ProgramState.privateKey, 
                        (ECPublicKeyParameters) pubKey, 
                        ProgramState.passphrase, 
                        key.getSymmetricKey());
                
                // Set symmetric key
                // update state to not receiving
                ProgramState.symmetricKey = deccryptedKey;
                ProgramState.KEY_EXCHANGE_REQUEST = false;
                ProgramState.KEY_RECEIVED = true;
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