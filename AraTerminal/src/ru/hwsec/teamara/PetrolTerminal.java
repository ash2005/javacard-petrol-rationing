package ru.hwsec.teamara;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Scanner;

import javacard.framework.Util;

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
    boolean updateBalance(short new_balance){
    	/* 
    	 * Construct msg that has to be signed.
    	 * [ termID |  Date   | Balance ]
    	 */
    	byte[] msg_bytes = new byte[18]; // Static.
    	String Date = this.get_date();
    	
		try {
			byte[] temp = new sun.misc.BASE64Decoder().decodeBuffer(Date);
			msg_bytes[0] = this.termID;
			System.arraycopy(temp, 0, msg_bytes, 1, temp.length);
			msg_bytes[16] = (byte)(new_balance);
			msg_bytes[17] = (byte)((new_balance >> 8) & 0xFF);
			
            if ( debug == true){
            	System.out.println("The message that has to be signed is:");
            	System.out.format("0x%x", this.termID);
            	System.out.println( Date + Short.toString(new_balance));
                for (byte b :  msg_bytes)
                	System.out.format("0x%x ", b);
            	System.out.println();
            	System.out.println();
            }
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
		byte[] msg_toSend_bytes = new byte[CARD_SIG_POS]; 
		System.arraycopy(msg_bytes, (short) 0, msg_toSend_bytes, (short) 0, (short) 18);
		/*
		 *  Create local signature in bytes from msg in bytes.
		 */
    	byte[] sig_term_bytes;
    	byte[] sig_term_bytes_padded = new byte[SIG_SIZE];
		try {
			sig_term_bytes = ECCTerminal.performSignature(msg_bytes);
			
			System.arraycopy(sig_term_bytes, (short) 0, sig_term_bytes_padded, (short) 0, (short) sig_term_bytes.length);
			System.arraycopy(sig_term_bytes_padded, (short) 0, msg_toSend_bytes, (short) 18, (short) SIG_SIZE);
			
			
            if ( debug == true){
            	System.out.println("Signature from terminal, length: " + sig_term_bytes.length);
                for (byte b :  sig_term_bytes)
                	System.out.format("0x%x ", b);
                System.out.println();
            }
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// Convert the signature to string to store it in the database.
		/*
		 * Alvin: There is no database for petrol terminal
    	String sig_term = new sun.misc.BASE64Encoder().encode(sig_term_bytes);
    	if (debug){
	    	System.out.println("Signature form terminal as String:");
	    	System.out.println(sig_term);
	    	System.out.println();
    	}
		*/
    	/*
    	 *  Send new balance and msg in bytes to the smart card and get the signature.
    	 */
		
		byte [] response;
		
		ResponseAPDU resp;
		try {
			resp = this.cardComm.sendToCard(new CommandAPDU(0,
					Instruction.UPDATE_BALANCE_PETROL, 0, 0, msg_toSend_bytes));
			response = resp.getData();
			if (response[0] == (byte) 0x01){
				System.out.println("Petrol Deduction is successful. You can withdraw fuel now.");
			}
			else{
				System.out.println("Petrol Deduction unsuccessful. Please try again.");
			}
			
			
		} catch (CardException ex) {
			System.out.println(ex.getMessage());
			System.out.println("Getting logs failed.");
		}
		
    	return true;
    }
    
    void use(){
    	System.out.println("Welcome to petrol pump terminal.");
    	
    	// get balance from smartcard. 
    	short balance = getBalance();
    	
    	// verify that balance > 1
    	if ( balance <= 1 ) {
    		System.out.println("The card does not have enough balance.");
    		System.exit(1);
    	}
    	
    	// ask for amount and verify that it is not lower than the balance. 
    	int amount = askForAmount(balance);
    	
    	// calculate new balance. 
    	short new_balance = (short) (balance - amount); 
    	
    	// perform an atomic operation of updating the 
    	// balance and storing the signatures to the smart card.
    	boolean status = updateBalance(new_balance);
    	if (!status){
    		System.out.println("Error, pumping failed.");
    		System.exit(1);
    	}
    	else
    		System.out.println("Pumping has been completed.");

    }

}
