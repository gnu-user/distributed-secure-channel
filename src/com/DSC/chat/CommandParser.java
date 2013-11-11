package com.DSC.chat;

import java.util.regex.Pattern;

public abstract class CommandParser {
	
	public static final String COMMAND_INDICATOR = "/";
	
	/**
	 * Check if the given string is a valid command
	 * @param entry
	 * @return
	 */
	public static boolean isCommand(String entry)
	{
		return Pattern.compile(COMMAND_INDICATOR + "((nick .*)|(quit)|(create)|(request))",
				Pattern.CASE_INSENSITIVE).matcher(entry).matches();
	}
	
	public static String rtrim(String s) {
	    int i = s.length()-1;
	    while (i >= 0 && Character.isWhitespace(s.charAt(i))) {
	        i--;
	    }
	    return s.substring(0,i+1);
	}

	public abstract boolean executeCommand();
}
