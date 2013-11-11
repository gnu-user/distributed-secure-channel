package com.DSC.chat;

import java.security.SecureRandom;
import java.util.regex.Pattern;

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
		
		// TODO Create the random symmetric key (256 bit key using ISAACRandomGenerator
		SecureRandom random = new SecureRandom();
		byte[] symmetricKey = new byte[16]; // 128 bit key
		
		random.nextBytes(symmetricKey);
		
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
