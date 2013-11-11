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
