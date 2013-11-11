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

public class Key implements SecureMessage
{
    private static final MessageType type = MessageType.KEY;
    private final String publicKey;
    private final String symmetricKey;
    private final String signature;

    public MessageType getType()
    {
        return Key.type;
    }

    public String getPublicKey()
    {
        return this.publicKey;
    }

    public String getSymmetricKey()
    {
        return this.symmetricKey;
    }

    public String getSignature()
    {
        return this.signature;
    }

    /**
     * 
     * @param publicKey
     * @param symmetricKey
     * @param signature
     */
    public Key(String publicKey, String symmetricKey, String signature)
    {
        this.publicKey = publicKey;
        this.symmetricKey = symmetricKey;
        this.signature = signature;
    }
}