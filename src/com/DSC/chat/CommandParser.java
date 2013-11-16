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
		return Pattern.compile(COMMAND_INDICATOR + "((nick .*)|(quit)|(create)|(join)|(request))",
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
