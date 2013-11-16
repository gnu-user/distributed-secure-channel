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

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.jgroups.Address;
import org.jgroups.JChannel;

import com.DSC.chat.CommandParser;
import com.DSC.chat.Create;
import com.DSC.chat.Join;
import com.DSC.chat.Nick;
import com.DSC.chat.Quit;
import com.DSC.chat.Request;
import com.DSC.controller.ReceiveController;
import com.DSC.controller.SendController;
import com.DSC.crypto.ECKey;
import com.DSC.message.MessageType;
import com.DSC.utility.ProgramState;
import com.google.common.collect.ConcurrentHashMultiset;

public class DistributedSecureChannel
{
    private static ReceiveController receiveController;
    private static SendController sendController;
    
    /**
     *
     * @throws Exception
     */
    private void join(String name) throws Exception
    {
        ProgramState.channel = new JChannel();
        ProgramState.channel.setDiscardOwnMessages(true);
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
                String line = in.readLine();
                
                if (CommandParser.isCommand(line))
                {
                	Nick nick;
                	Quit quit;
                	Create create;
                	Join join;
                	Request request;
                	
                	if ((nick = Nick.parse(line)) != null)
	                {
                		nick.executeCommand();
                		System.out.println("> User nick changed to " + nick.getNick());
	                }
                	else if ((quit = Quit.parse(line)) != null)
                	{
            			// Returns false if the state was null.
            			quit.executeCommand();
 	                    break;
                	}
                	else if ((create = Create.parse(line)) != null)
	                {
                		System.out.print("> Enter the channel name: ");
                		String channelName = in.readLine();
                		System.out.print("> Enter the channel passphrase: ");
                		String passphrase = in.readLine();
                		create.setChannel(channelName);
                		create.setPassphrase(passphrase);
                		
                		if (create.executeCommand())
                		{
                			if (ProgramState.channel == null)
                			{
                			    join(channelName);                		
                			    System.out.println("> Channel " + channelName + " created.");
                			}
                		}
                		else
                		{
                			System.out.println("> Channel " + channelName + " has failed to create");
                		}
	                    
	                }
                	else if ((join = Join.parse(line)) != null)
                	{
                        System.out.print("> Enter the channel to join: ");
                        String channelName = in.readLine();
                        join.setChannel(channelName);
                        
                        if (join.executeCommand())
                        {                            
                            if (ProgramState.channel == null || ! ProgramState.channel.equals(channelName))
                            {
                                join(channelName);
                            }
                        }
                        else
                        {
                            System.out.println("> Invalid channel name");
                        }
                	}
                	else if ((request = Request.parse(line)) != null)
	                {
                		System.out.print("> Enter the channel to request access: ");
                		String channelName = in.readLine();
                		System.out.print("> Enter authentication: ");
                		String passphrase = in.readLine();
                		request.setChannel(channelName);
                		request.setPassphrase(passphrase);
                		
                		if (request.executeCommand())
                		{
                		
	                		System.out.println("> Signing key...");
	                		//TODO sign key
	                		
	                		System.out.println("> Requesting access...");
	                		//TODO request access (with timeout)
	                		
		                    // Send out the request to join
		                    sendController.send(MessageType.AUTH_REQUEST, null, null);
                		}
                		else
                		{
                			System.out.println("> An unspecified error occurred.");
                		}
	                }
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
        ECKey key = new ECKey();
        key.init();
        ProgramState.publicKey = (ECPublicKeyParameters) key.getPublic();
        ProgramState.privateKey = (ECPrivateKeyParameters) key.getPrivate();
        
        // Create the blacklist and trusted contacts
        ProgramState.blacklist =  ConcurrentHashMultiset.create();
        ProgramState.trustedKeys = ConcurrentHashMultiset.create();
        
        
        // Set a default nick?
        // Initialize ISAACRandomGenerator, set ProgramState.IVEngine
        // Start eventloop
        receiveController = new ReceiveController();
        sendController = new SendController();

        new DistributedSecureChannel().eventLoop();
    }

}
