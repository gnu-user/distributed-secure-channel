package com.DSC.chat;

import java.util.regex.Pattern;

import com.DSC.utility.ProgramState;

public class Quit extends CommandParser {
	
	public static Quit parse(String entry) {
		entry = rtrim(entry);
		String[] elements = entry.split(" ");
		
		if(elements.length == 1)
		{
			if(Pattern.compile(COMMAND_INDICATOR + "quit",
					Pattern.CASE_INSENSITIVE).matcher(elements[0]).matches())
			{
				return new Quit();
			}
		}
		return null;
	}

	@Override
	public boolean executeCommand() {
		if (ProgramState.channel != null)
        {
			ProgramState.channel.close();
			return true;
        }
		return false;
	}

}
