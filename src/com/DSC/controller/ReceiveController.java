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

import org.jgroups.Message;
import org.jgroups.ReceiverAdapter;

import com.DSC.message.*;

public class ReceiveController extends ReceiverAdapter
{
    /**
     * 
     * @param msg
     */
    @Override
    public void receive(Message msg)
    {
        throw new UnsupportedOperationException();
    }

    /**
     * 
     * @param msg
     */
    private void authRequestHandler(SecureMessage msg)
    {
        throw new UnsupportedOperationException();
    }

    /**
     * 
     * @param msg
     */
    private void authAcknowledgeHander(SecureMessage msg)
    {
        throw new UnsupportedOperationException();
    }

    /**
     * 
     * @param msg
     */
    private void keyExchangeHandler(SecureMessage msg)
    {
        throw new UnsupportedOperationException();
    }

    /**
     * 
     * @param msg
     */
    private void keyHandler(SecureMessage msg)
    {
        throw new UnsupportedOperationException();
    }

    /**
     * 
     * @param msg
     */
    private void encryptedMessageHandler(SecureMessage msg)
    {
        throw new UnsupportedOperationException();
    }

}