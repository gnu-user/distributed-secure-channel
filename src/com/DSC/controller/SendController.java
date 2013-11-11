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

import org.jgroups.Address;
import org.jgroups.Message;

import com.DSC.crypto.ECDSA;
import com.DSC.message.*;
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
                    keyHandler();
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
        BigInteger[] signature = ECDSA.signAuthRequest(
                ProgramState.privateKey, 
                ProgramState.publicKey, 
                ProgramState.passphrase);
        
        /* Create an authentication request message */
        SecureMessage secureMsg = AbstractMessageFactory.createMessage(
                MessageType.AUTH_REQUEST, 
                ProgramState.publicKey, 
                null, 
                null, 
                signature);  
        
        /* Send the message using Jgroups */
        Message msg = new Message(null, null, secureMsg);
        ProgramState.channel.send(msg);
    }

    /**
     * 
     * @param authKey
     */
    private void authAcknowledgeHandler(Object authKey)
    {
        throw new UnsupportedOperationException();
    }

    private void keyExchangeHandler()
    {
        throw new UnsupportedOperationException();
    }

    private void keyHandler()
    {
        throw new UnsupportedOperationException();
    }

    /**
     * 
     * @param msg
     */
    private void encryptedMessageHandler(Object msg)
    {
        throw new UnsupportedOperationException();
    }

}