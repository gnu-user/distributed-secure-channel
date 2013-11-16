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
