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
import com.DSC.utility.Colour;
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
                    authAcknowledgeHandler(secureMsg, msg.getSrc());
                    break;
                case KEY_EXCHANGE:
                    keyExchangeHandler(secureMsg, msg.getSrc());
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
            System.out.println(Colour.RED + cte.getMessage() + Colour.RESET);
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
        /* Only accept requests if authenticated */
        if (! ProgramState.AUTHENTICATED)
        {
            return;
        }
                
        AuthRequest authRequest = (AuthRequest) msg;
        
        ECPublicKeyParameters pubKey = ECGKeyUtil.decodePubKey(authRequest.getPublicKey());
        String strPubKey = new String(Hex.encode(authRequest.getPublicKey()));
        
        ProgramState.AUTHENTICATION_DECISION = true;
                        
        System.out.println("\n> Received key exchange from: " + src.toString());
        System.out.print("> Verify/Reject/Ignore (V/R/I): "); 
        String choice = waitForInput();
        
        if (choice.equalsIgnoreCase("v"))
        {
            if (ECDSA.verifyAuthRequest(pubKey, ProgramState.passphrase, authRequest.getSignature()))
            {
                System.out.println(Colour.GREEN + "> Signature valid." + Colour.RESET);
                System.out.print("> Trust new member? (Y/N): ");
                
                if (waitForInput().equalsIgnoreCase("y"))
                {
                    /* Update list of trusted members */
                    System.out.println("> Updating list of trusted members...");
                    if (! ProgramState.trustedKeys.containsKey(strPubKey))
                    {
                        ProgramState.trustedKeys.put(strPubKey, src);
                    }
                    
                    /* Send authenticated acknowledgement msg */
                    System.out.println(Colour.YELLOW + "> Authenticated member announced." + Colour.RESET);
                    SendController sendController = new SendController();
                    sendController.send(MessageType.AUTH_ACKNOWLEDGE, pubKey, null);
                    
                    /* Update state */
                    ProgramState.AUTHENTICATION_ACKNOWLEDGE = true;
                }
            }
            else
            {
                System.out.println(Colour.RED + "> Signature invalid." + Colour.RESET);
                System.out.print("> Ignore sender permanently? (Y/N): ");
                
                /* ban permanently if yes */
                if (waitForInput().equalsIgnoreCase("y"))
                {
                    ProgramState.blacklist.add(src);    
                    System.out.println(Colour.YELLOW + "> Sender ignored permanently." + Colour.RESET);
                }
            }
        }
        else if (choice.equalsIgnoreCase("i"))
        {
            System.out.print("> Ignore sender permanently? (Y/N): ");
            
            /* ban permanently if yes */
            if (waitForInput().equalsIgnoreCase("y"))
            {
                ProgramState.blacklist.add(src);    
                System.out.println(Colour.YELLOW + "> Sender ignored permanently." + Colour.RESET);
            }
        }
        
        ProgramState.AUTHENTICATION_DECISION = false;
    }


    /**
     * 
     * @param msg
     * @param src
     */
    private void authAcknowledgeHandler(SecureMessage msg, Address src)
    {
        /* Check if in requesting authentication state */
        if (! ProgramState.AUTHENTICATION_REQUEST)
        {
            return;
        }
        
        AuthAcknowledge authAcknowledge = (AuthAcknowledge) msg;
        
        ECPublicKeyParameters pubKey = ECGKeyUtil.decodePubKey(authAcknowledge.getPublicKey());
        ECPublicKeyParameters authKey = ECGKeyUtil.decodePubKey(authAcknowledge.getAuthKey());
        String strPubKey = new String(Hex.encode(authAcknowledge.getPublicKey()));
        
        /* Check if acknowledge valid */
        if (ECDSA.verifyAuthAcknowledge(pubKey, authKey, ProgramState.passphrase, authAcknowledge.getSignature()))
        {
            /* Add the client that acknowledged as trusted (for client requesting access) */
            if (! ProgramState.trustedKeys.containsKey(strPubKey))
            {
                ProgramState.trustedKeys.put(strPubKey, src);
            }
            
            ProgramState.AUTHENTICATED = true;
        }
    }


    /**
     * 
     * @param msg
     * @param src
     */
    private void keyExchangeHandler(SecureMessage msg, Address src)
    {
        /* Check if awaiting key request state after acknowledgment */
        if (! (ProgramState.AUTHENTICATED && ProgramState.AUTHENTICATION_ACKNOWLEDGE))
        {
            return;
        }
        
        KeyExchange keyExchange = (KeyExchange) msg;
        
        ECPublicKeyParameters pubKey = ECGKeyUtil.decodePubKey(keyExchange.getPublicKey());
        String strPubKey = new String(Hex.encode(keyExchange.getPublicKey()));
        
        if (! ProgramState.trustedKeys.containsKey(strPubKey))
        {
            return;
        }
        
        /* Check if key received valid */
        if (ECDSA.verifyKeyExchange(pubKey, ProgramState.passphrase, keyExchange.getSignature()))
        {
            /* Send the encrypted symmetric key */
            SendController sendController = new SendController();
            sendController.send(MessageType.KEY, pubKey, src);
            
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
        /* Check state, if authenticated and awaiting key exchange */
        if (! (ProgramState.AUTHENTICATED && ProgramState.KEY_EXCHANGE_REQUEST))
        {
            return;
        }
        
        Key key = (Key) msg;
        
        ECPublicKeyParameters pubKey = ECGKeyUtil.decodePubKey(key.getPublicKey());
        String strPubKey = new String(Hex.encode(key.getPublicKey()));
        
        /* If from trusted contact */
        if (ProgramState.trustedKeys.containsKey(strPubKey))
        {
            /* Verify key */
            if (ECDSA.verifyKey(pubKey, key.getSymmetricKey(), ProgramState.passphrase, key.getSignature()))
            {   
                /* Decrypt the symmetric key */
                byte[] deccryptedKey = Cipher.decryptKey(
                        ProgramState.privateKey, 
                        (ECPublicKeyParameters) pubKey, 
                        ProgramState.passphrase, 
                        key.getSymmetricKey());
                
                /* Set symmetric key & update state to not receiving */
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
        if (! (ProgramState.AUTHENTICATED && ProgramState.KEY_RECEIVED))
        {
            return;
        }
        
        EncryptedMessage encryptedMessage = (EncryptedMessage) msg;
       
        /* Only decrypt if the message HMAC is valid */
        if (Cipher.verifyHMAC(ProgramState.passphrase, encryptedMessage.getHMAC(), 
                encryptedMessage.getMessage()))
        {            
            /* Decrypt the message */
            byte[] message = Cipher.decryptMsg(
                    ProgramState.symmetricKey, 
                    encryptedMessage.getIV(), 
                    encryptedMessage.getMessage());
            
            /* Remove the current line from prompt */
            String delete = "";
            for (int i = 0; i < new String(ProgramState.nick + "> ").length(); ++i)
            {
                delete += "\b";
            }
            
            System.out.println(delete + new String(message));
            System.out.print(ProgramState.nick + "> ");
        }
    }
    
    
    /**
     * Method to handle concurrent access to the terminal input from the user
     * @return
     */
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
}