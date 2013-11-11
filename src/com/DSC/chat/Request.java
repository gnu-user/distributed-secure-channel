package com.DSC.chat;

import java.util.regex.Pattern;

import com.DSC.utility.ProgramState;

public class Request extends CommandParser{
	
	private String channel;
	private String passphrase;

	public static Request parse(String entry) {
		entry = rtrim(entry);
		String[] elements = entry.split(" ");
		
		if(elements.length == 1)
		{
			if(Pattern.compile(COMMAND_INDICATOR + "request",
					Pattern.CASE_INSENSITIVE).matcher(elements[0]).matches())
			{
				return new Request();
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
