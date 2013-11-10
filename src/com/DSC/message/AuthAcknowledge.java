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

public class AuthAcknowledge implements Message
{
    private static final MessageType type = MessageType.AUTH_ACKNOWLEDGE;
    private final String publicKey;
    private final String authKey;
    private final Timestamp timestamp;
    private final String signature;

    public MessageType getType()
    {
        return AuthAcknowledge.type;
    }

    public String getPublicKey()
    {
        return this.publicKey;
    }

    public String getAuthKey()
    {
        return this.authKey;
    }

    public Timestamp getTimeStamp()
    {
        return this.timestamp;
    }

    public String getSignature()
    {
        return this.signature;
    }

    /**
     * 
     * @param type
     * @param publicKey
     * @param authKey
     * @param timestamp
     * @param signature
     */
    public AuthAcknowledge(String publicKey, String authKey, Timestamp timestamp, String signature)
    {
        this.publicKey = publicKey;
        this.authKey = authKey;
        this.timestamp = timestamp;
        this.signature = signature;
    }
}