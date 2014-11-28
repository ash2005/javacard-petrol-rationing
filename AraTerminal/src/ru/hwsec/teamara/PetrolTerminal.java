package ru.hwsec.teamara;

import java.util.List;
import java.util.Scanner;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;


public class PetrolTerminal extends AraTerminal {

    public PetrolTerminal(byte ttermID){
        super(ttermID); // set the terminal ID.
    }

    /* Check the revocation status of the card.
     * Return false if revoked.
     * Do not proceed further and end all communications with the card.*/
    private boolean checkRevoke(){
    	return true;
    }
    
    /*
     * Send instruction START_PUMPING to the card and
     * retrieve the balance.
     */
    private int getBalance(){
    	
    	return 2;
    }

    /* 
     * Get requested fuel withdrawal amount from car owner 
     * and verify that there is enough balance.
     */
    private int askForAmount(int balance){
        System.out.print("Enter amount: ");
        String newLine = System.getProperty("line.separator");// Retrieve line separator dependent on OS.
        boolean done = false;
        
        while (!done){
	        Scanner in = new Scanner( System.in );
	        try{
	        	int amount = Integer.parseInt(in.next());
	        	if ( amount > balance )
	        		throw new IllegalStateException("");
	        	done = true;
	        	return amount;
	        } catch(NumberFormatException ex) {
	        	System.out.print("invalid number " + newLine + newLine + "try again: ");
	        } catch(IllegalStateException ex){
	    		System.out.println("not have enough balance " + newLine + newLine + "try again:");
	        } catch (Exception ex) {
	            System.out.println("IO error.");
	            System.exit(1);
	        }
        }
    	return 1;
    }

    
    /* Reference sec 7.4 of Design Document
     * Call this function if verifyBalance returns true
     * Create message and signature to update card balance.
     */
    boolean updateBalance(short new_balance, String msg){
    	return true;
    }
    
    void use(){
    	System.out.println("Welcome to petrol pump terminal.");
    	
    	// get balance from smartcard. 
    	int balance = getBalance();
    	
    	// verify that balance > 0
    	if ( balance <= 1 ) {
    		System.out.println("The card does not have enough balance.");
    		System.exit(1);
    	}
    	
    	// ask for amount and verify that it is not lower than the balance. 
    	int amount = askForAmount(balance);
    	
    	// calculate new balance. 
    	short new_balance = (short) (balance - amount); 
    	
    	// construct the message that has to be signed by both the terminal and the smart card.
    	String msg = Integer.toString(this.termID) +  Integer.toString(new_balance) + this.get_date();
    	
    	// perform an atomic operation of updating the 
    	// balance and storing the signatures to the smart card.
    	boolean status = updateBalance(new_balance, msg);
    	if (!status){
    		System.out.println("Error, pumping failed.");
    		System.exit(1);
    	}
    	else
    		System.out.println("Charging has been completed.");

    }

}
