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
package com.DSC.chat;

import java.security.SecureRandom;
import java.util.regex.Pattern;

import org.bouncycastle.crypto.engines.ISAACEngine;

import com.DSC.crypto.ISAACRandomGenerator;
import com.DSC.utility.ProgramState;

public class Create extends CommandParser {

	private String channel;
	private String passphrase;
	
	public static Create parse(String entry) {
		entry = rtrim(entry);
		String[] elements = entry.split(" ");
		
		if(elements.length == 1)
		{
			if(Pattern.compile(COMMAND_INDICATOR + "create",
					Pattern.CASE_INSENSITIVE).matcher(elements[0]).matches())
			{
				return new Create();
			}
		}
		return null;
	}

	
	@Override
	public boolean executeCommand() {
		
		if (!Pattern.matches("[a-zA-Z_\\s0-9-]+", this.channel))
		{
			return false;
		}
		
		// Generate seed
		byte[] seed = new byte[64]; // 512 bit seed 
		SecureRandom random = new SecureRandom();
		random.nextBytes(seed);

		// Create the symmetric key
		byte[] symmetricKey = new byte[16]; // 128 bit key
		ISAACRandomGenerator isaac = new ISAACRandomGenerator(new ISAACEngine());
		isaac.init(seed);
		isaac.nextBytes(symmetricKey);
		ProgramState.symmetricKey = symmetricKey;
		
		ProgramState.passphrase = this.passphrase;
		return true;
	}
	
	public void setChannel(String channel)
	{
		this.channel = channel;
	}
	
	public void setPassphrase(String passphrase)
	{
		this.passphrase = passphrase;
	}
}
