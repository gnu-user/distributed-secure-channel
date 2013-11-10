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

public class EncryptedMessage implements Message
{
    private static final MessageType type = MessageType.ENCRYPTED_MESSAGE;
    private final String IV;
    private final String message;
    private final String signature;

    public MessageType getType()
    {
        return EncryptedMessage.type;
    }

    public String getIV()
    {
        return this.IV;
    }
    
    public String getMessage()
    {
        return this.message;
    }

    public String getSignature()
    {
        return this.signature;
    }

    /**
     *
     * @param IV
     * @param message
     * @param signature
     */
    public EncryptedMessage(String IV, String message, String signature)
    {
        this.IV = IV;
        this.message = message;
        this.signature = signature;
    }
}