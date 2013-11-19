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
