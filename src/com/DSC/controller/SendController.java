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

import org.jgroups.Address;

import com.DSC.message.*;

public class SendController
{

    /**
     * 
     * @param type
     * @param msg
     */
    public void send(MessageType type, String data, Address dest)
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

    private void authRequestHandler()
    {
        throw new UnsupportedOperationException();
    }

    /**
     * 
     * @param authKey
     */
    private void authAcknowledgeHandler(String authKey)
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
    private void encryptedMessageHandler(String msg)
    {
        throw new UnsupportedOperationException();
    }

}