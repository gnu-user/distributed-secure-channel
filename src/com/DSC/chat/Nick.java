package com.DSC.chat;

import java.util.regex.Pattern;

import com.DSC.utility.ProgramState;

public class Nick extends CommandParser {
	
	private String nickname;
	
	public Nick (String nickname)
	{
		this.nickname = nickname;
	}

	@Override
	public boolean executeCommand() {
		ProgramState.nick = this.nickname;
		return true;
	}

	public static Nick parse(String entry) {
		entry = rtrim(entry);
		String[] elements = entry.split(" ");
		
		if(elements.length == 2)
		{
			if(Pattern.compile(COMMAND_INDICATOR + "nick",
					Pattern.CASE_INSENSITIVE).matcher(elements[0]).matches())
			{
				//Ensure valid username
				if(Pattern.matches("[a-zA-Z_0-9]+", elements[1]))
				{
					return new Nick(elements[1]);
				}
			}
		}
		return null;
	}
	
	public String getNick()
	{
		return nickname;
	}
}
