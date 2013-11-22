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
package com.DSC.utility;

public class InputSymbol {

    private boolean inputWait = false;
    private String input = null;
    
    public synchronized void setInputWait() 
    { 
    	inputWait = false;
    	notifyAll();
    }
    
    public synchronized void setInputReady(String input) 
    { 
    	setInput(input);
    	inputWait = true;
    	notifyAll();
    }
    
    public synchronized boolean getInputWait() 
    { 
    	return inputWait;
    }

	/**
	 * @return the value
	 */
	public synchronized String getInput() {
		return input;
	}

	/**
	 * @param value the value to set
	 */
	private void setInput(String input) {
		this.input = input;
	}

	public synchronized void resetInput() {
		this.input = null;
	}
}
