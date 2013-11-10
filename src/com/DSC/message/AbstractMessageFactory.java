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
package com.DSC.message;

import java.sql.Timestamp;

public abstract class AbstractMessageFactory implements MessageFactory
{
    /**
     * 
     * @param type
     * @param publicKey
     * @param IV
     * @param other
     * @param timestamp
     * @param signature
     * @throws IllegalArgumentException
     */
    public Message createMessage(MessageType type, String publicKey, String IV, String other, 
            Timestamp timestamp, String signature) throws IllegalArgumentException
    {
        switch (type)
        {
            case AUTH_REQUEST:
                return createAuthRequest(publicKey, signature);
            case AUTH_ACKNOWLEDGE:
                return createAuthAcknowledge(publicKey, other, timestamp, signature);
            case KEY_EXCHANGE:
                return createKeyExchange(publicKey, signature);
            case KEY:
                return createKey(publicKey, other, signature);
            case ENCRYPTED_MESSAGE:
                return createEncryptedMessage(IV, other, signature);
            default:
                throw new IllegalArgumentException("Invalid message type!");
        }
    }

    /**
     * 
     * @param publicKey
     * @param signature
     * @throws IllegalArgumentException
     */
    private Message createAuthRequest(String publicKey, String signature)
            throws IllegalArgumentException
    {
        /* Argument checking */
        if (publicKey == null || signature == null)
        {
            throw new IllegalArgumentException("Invalid AuthRequest message arguments!"); 
        }
        
        return new AuthRequest(publicKey, signature);
    }

    /**
     * 
     * @param publicKey
     * @param authKey
     * @param timestamp
     * @param signature
     * @throws IllegalArgumentException
     */
    private Message createAuthAcknowledge(String publicKey, String authKey, Timestamp timestamp, String signature) 
            throws IllegalArgumentException
    {
        /* Argument checking */
        if (publicKey == null || authKey == null || timestamp == null || signature == null)
        {
            throw new IllegalArgumentException("Invalid AuthAcknowledge message arguments!"); 
        }
        
        return new AuthAcknowledge(publicKey, authKey, timestamp, signature);
    }

    /**
     * 
     * @param publicKey
     * @param signature
     * @throws IllegalArgumentException
     */
    private Message createKeyExchange(String publicKey, String signature) 
            throws IllegalArgumentException
    {
        /* Argument checking */
        if (publicKey == null || signature == null)
        {
            throw new IllegalArgumentException("Invalid KeyExchange message arguments!"); 
        }
        
        return new KeyExchange(publicKey, signature);
    }

    /**
     * 
     * @param publicKey
     * @param symmetricKey
     * @param signature
     * @throws IllegalArgumentException
     */
    private Message createKey(String publicKey, String symmetricKey, String signature) 
            throws IllegalArgumentException
    {
        /* Argument checking */
        if (publicKey == null || symmetricKey == null || signature == null)
        {
            throw new IllegalArgumentException("Invalid AuthRequest message arguments!"); 
        }
        
        return new Key(publicKey, symmetricKey, signature);
    }

    /**
     * 
     * @param IV
     * @param message
     * @param signature
     * @throws IllegalArgumentException
     */
    private Message createEncryptedMessage(String IV, String message, String signature) 
            throws IllegalArgumentException
    {
        /* Argument checking */
        if (IV == null || message == null || signature == null)
        {
            throw new IllegalArgumentException("Invalid EncryptedMessage message arguments!"); 
        }
        
        return new EncryptedMessage(IV, message, signature);
    }
}