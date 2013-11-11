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
package com.DSC.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import com.DSC.controller.*;
import com.DSC.utility.ProgramState;

import org.jgroups.JChannel;
import org.jgroups.Message;

public class DistributedSecureChannel
{
    private static ReceiveController receiveController;
    
    /**
     * 
     * @throws Exception
     */
    private void join(String name) throws Exception
    {
        ProgramState.channel = new JChannel();
        ProgramState.channel.setReceiver(receiveController);
        ProgramState.channel.connect(name);
    }
    
    /**
     * The main eventLoop that handles the user input for the IRC client
     */
    private void eventLoop()
    {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        
        while (true)
        {
            try
            {
                System.out.flush();
                System.out.print("> ");
                String line = in.readLine().toLowerCase();
                
                if (line.startsWith("/quit"))
                {
                    if (ProgramState.channel != null)
                    {
                        ProgramState.channel.close();
                    }
                    break;
                }
                else if (line.startsWith("/create"))
                {
                    // Create the random symmetric key (256 bit key using ISAACRandomGenerator
                    // Set the channel passphrase
                    // Join the channel
                    join("channel name");
                }
                else
                {
                    // Send a message
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }
    }
    
    
    /**
     * @param args
     */
    public static void main(String[] args)
    {
        // Create their private & public keys
        // Set a default nick?
        // Initialize ISAACRandomGenerator, set ProgramState.IVEngine
        // Start eventloop
        receiveController = new ReceiveController();
    }

}
