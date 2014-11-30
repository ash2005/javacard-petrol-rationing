package ru.hwsec.teamara;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Scanner;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class PetrolTerminal extends AraTerminal {

    public PetrolTerminal(byte ttermID){
        super(ttermID); // set the terminal ID.
    }

    /* 
     * Get requested fuel withdrawal amount from car owner 
     * and verify that there is enough balance.
     */
    private int askForAmount(int balance){
        int amount = 0;
        System.out.print("Enter amount: ");
        Scanner in = new Scanner( System.in );
        while(true){	        
	        try{
	        	amount = Integer.parseInt(in.next());
	        	if ( amount > balance )
	        		System.out.println("There is not enough balance on the card.");
	        	else
	        		break;
	        } catch(NumberFormatException ex) {
	        	System.out.print("Invalid integer, try again: ");
	        }
        }
        return amount;
    }

    
    /* Reference sec 7.4 of Design Document
     * Call this function if verifyBalance returns true
     * Create message and signature to update card balance.
     */
    boolean updateBalance(short newBalance){
    	/* 
    	 * Construct msg that has to be signed.
    	 * [ termID |  Date   | Balance ]
    	 */
    	byte[] payloadBytes = new byte[TERM_SIG_POS]; // 2 Bytes for the balance.
    	byte[] messageBytes = new byte[UPDATE_BALANCE_PETROL_LENGTH];
    	byte[] temp = {};
    	String date = this.get_date();

		try {
			//temp = new sun.misc.BASE64Decoder().decodeBuffer(date);
			//String test = new sun.misc.BASE64Encoder().encode(temp);
			temp = date.getBytes(Charset.forName("UTF-8"));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		payloadBytes[0] = this.termID;
		System.arraycopy(temp, 0, payloadBytes, 1, temp.length);
		if (temp.length != DATE_SIZE){
			System.out.println("System call get_date() uses different length than the designed.");
			System.exit(1);
		}
		payloadBytes[BALANCE_POS] = (byte)(newBalance);
		payloadBytes[BALANCE_POS+1] = (byte)((newBalance >> 8) & 0xFF);
    	System.out.println("SIZE: " + payloadBytes.length + " BALANCE_POS: " + BALANCE_POS);
        if (debug == true){
        	System.out.println("The message that has to be signed is:");
        	System.out.format("0x%x", this.termID);
        	System.out.println(date + Short.toString(newBalance));
            for (byte b : payloadBytes)
            	System.out.format("0x%x ", b);
        	System.out.print("\n\n");
        }
		System.arraycopy(payloadBytes, (short) 0, messageBytes, (short) 0, (short) TERM_SIG_POS);
		
		/*
		 *  Create local signature in bytes from msg in bytes.
		 */
    	byte[] signatureBytes;
    	byte[] sig_term_bytes_padded = new byte[SIG_SIZE];
		try {
			signatureBytes = ECCTerminal.performSignature(payloadBytes);
			
			System.arraycopy(signatureBytes, (short) 0, sig_term_bytes_padded, (short) 0, (short) signatureBytes.length);
			System.arraycopy(sig_term_bytes_padded, (short) 0, messageBytes, (short) TERM_SIG_POS, (short) SIG_SIZE);
			
			
            if ( debug == true){
            	System.out.println("Signature from terminal, length: " + signatureBytes.length);
                for (byte b :  signatureBytes)
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
					Instruction.UPDATE_BALANCE_PETROL, 0, 0, messageBytes));
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
