package ru.hwsec.teamara;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javacard.security.CryptoException;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;



public class ChargingTerminal extends AraTerminal {

	/*
	 * Class used to represent the card that it is used at the moment.
	 */
	public class Card {
		protected int cardID;
		protected short balance;
		public Card(){
			
		}
		public Card(int cardID, short balance) {
			this.cardID = cardID;
			this.balance = balance;
		}
	}
	
	/* Charging terminal is online and has access to the database. */
	private MySql db;
	
	public ChargingTerminal(MySql tdb, byte ttermID){
        super(ttermID); // set the terminal ID.
        this.db = tdb;
    }

	/**
     * Get card logs adn store them in the database.
     * 
     * Additionally,    TODO
     * Check if the card logs fulfil specified criteria
     *  - less than 200 litres per month
     *  - Only 5 withdrawals
	 * @param card obj Card with the details of the connected card.
	 * @return true/false depending on success.
	 */
	private boolean getLogs(Card card) {
        ResponseAPDU resp;
    	boolean status = true;
    	
    	// The buffer that temporary stores the logs. 
    	byte[] buffer = new byte[MAX_LOGS*LOG_SIZE];
    	Arrays.fill( buffer, (byte) 0x00 );

    	// Size of the buffer that contains usefull information.
    	int buffer_size = 0;
    	
        try {
        	resp = this.cardComm.sendToCard(new CommandAPDU(0, Instruction.GET_LOGS, 1, 0));
			byte[] temp = resp.getData();
			buffer_size = temp.length;
            if ( debug == true){
            	System.out.println("In function getLogs..");
            	for (byte b :  temp)
            		System.out.format("0x%x ", b);
            	System.out.println();
            }
			if (temp[0] == (byte) 0xFF) // Signal that defines that card logs are empty.
				return true;
			// copy bytes to the buffer.
			System.arraycopy(temp, 0, buffer, 0, buffer_size);			
		} catch (CardException ex) {
			System.out.println(ex.getMessage());
			System.out.println("Getting logs failed.");
			System.exit(1);
		}

		int number_of_logs = 0;
		try {
			number_of_logs = (buffer_size + 1) / LOG_SIZE;
			if (number_of_logs > 5) // Maximum log capacity is 5.
				throw new IllegalStateException("Cannot handle " + number_of_logs + " logs.");
        } catch(NumberFormatException ex) {
        	System.out.print(ex.getMessage());
		} catch (IllegalStateException ex) {
			System.out.println(ex.getMessage());
		}
		
		// Decode each log and store it in the database.
		for ( int i = 0; i < number_of_logs; i++){
			int index = 0 + i * LOG_SIZE; // Starting index of each log.
			
			int ttermID = (int) buffer[index];
			short balance = (short) (buffer[BALANCE_POS] | (buffer[BALANCE_POS+1] << 8 ));
			short transaction = (short) 1; // transaction must be calculated in a later version.
			byte date_bytes[] = new byte[DATE_SIZE]; 
			byte sig_term_bytes[] = new byte[SIG_SIZE];
			byte sig_card_bytes[] = new byte[SIG_SIZE];
			// copy bytes to the buffer.
			System.arraycopy(buffer, index + DATE_POS,     date_bytes,     0, DATE_SIZE);			
			System.arraycopy(buffer, index + TERM_SIG_POS, sig_term_bytes, 0, SIG_SIZE);
			System.arraycopy(buffer, index + CARD_SIG_POS, sig_card_bytes, 0, SIG_SIZE);
			
			String date     = new sun.misc.BASE64Encoder().encode(date_bytes);
			String sig_term = new sun.misc.BASE64Encoder().encode(sig_term_bytes);
			String sig_card = new sun.misc.BASE64Encoder().encode(sig_card_bytes);
			
			status = db.addlog(card.cardID, balance, transaction, ttermID, date, sig_card, sig_term);
	    	if (!status){
	    		System.out.println("Storing logs failed.");
	    		System.exit(1);
	    	}
		}
        return true;
    }
	
	/**
	 * Just send command CLEAR LOGS to the smartcard.
	 */
	private boolean clearLogs(){
		try {
			this.cardComm.sendToCard(new CommandAPDU(0, Instruction.CLEAR_LOGS, 1, 0));
			return true;
		} catch (CardException ex) {
			System.out.println(ex.getMessage());
			return false;
		}
	}

	/**
	 * Compare the cardID's balance at the smart card and at the database.
	 */
	private boolean verifyBalance(Card card){
		int tbalance = db.get_balance(card.cardID);
		if ( tbalance == card.balance)
			return true;
		else if (tbalance == -1)
			System.out.println("cardID: " + card.cardID + " has not been found.");
		else if (tbalance == -2)
			System.out.println("SQL error");		
		return false;
	}
	
    /* Revoke the card if backend database has revoke flag set for that card*/
    private boolean revoke(){
    	return true;
    }

    /**
     * Perform an atomic operation. TODO!!!
     * - Sign the message
     * - Send message and new balance to the smart card
     * - Get the signature
     * - Store the message and the signatures to the database
     */
    private boolean updateBalance(Card card, short new_balance){
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
			msg_bytes[16] = (byte) (new_balance    & 0xFF);
			msg_bytes[17] = (byte) (new_balance>>8 & 0xFF);
			
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
		
		/*
		 *  Create local signature in bytes from msg in bytes.
		 */
    	byte[] sig_term_bytes = new byte[SIG_SIZE];
		try {
			sig_term_bytes = ECCTerminal.performSignature(msg_bytes);
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
    	String sig_term = new sun.misc.BASE64Encoder().encode(sig_term_bytes);
    	if (debug){
	    	System.out.println("Signature form terminal as String:");
	    	System.out.println(sig_term);
	    	System.out.println();
    	}
		
    	/*
    	 *  Send new balance and msg in bytes to the smart card and get the signature.
    	 */
		byte[] sig_card_bytes = new byte[SIG_SIZE];
		ResponseAPDU resp;
		try {
			resp = this.cardComm.sendToCard(new CommandAPDU(0,
					Instruction.UPDATE_BALANCE_CHARGE, 0, 0, msg_bytes));
			sig_card_bytes = resp.getData();
			if (debug == true) {
				System.out.println("Reply for UPDATE_BALANCE_CHARGE, the signature of smartcard is:");
				for (byte b : sig_card_bytes)
					System.out.format("0x%x ", b);
				System.out.println();
				try{
					System.out.println(ECCTerminal.performSignatureVerification(msg_bytes, sig_card_bytes, super.cardKeyBytes));
					
				}
				catch (GeneralSecurityException e){
					System.out.println("Signature Verification Error");
				}
				
			}
		} catch (CardException ex) {
			System.out.println(ex.getMessage());
			System.out.println("Getting logs failed.");
		}
		// Convert the signature to string to store it in the database.
		String sig_card = new sun.misc.BASE64Encoder().encode(sig_card_bytes);
		if (debug) {
			System.out.println("Signature form card as String:");
			System.out.println(sig_card.length());
			System.out.println();
		}
    	// Verify signature of smart card.
    	// ECCTerminal.performSignatureVerification(msg, sig_card_bytes, this.cardKeyBytes)
    	if ( debug ){
    		//System.exit(1);
    	}
    	// Save log entry to the database.
    	db.addlog(card.cardID, card.balance, this.MONTHLY_ALLOWANCE, (int)this.termID, this.get_date(), sig_card, sig_term);
    	
    	// Update balance in table sara_card
    	db.updateBalance(card.cardID, new_balance);
    	
    	return true;
    }
    
    void use (){
    	System.out.println("Welcome to charging terminal.");
    	
    	// exit if it turns false. 
    	boolean status = true;
    	// object that describes the connected card. 
    	Card card = new Card( (int) 0xA1, (short) 100 );  
    	
    	// retrieve and store logs as well as get the basic info of the card.
    	status = getLogs(card);

    	// if getting logs was successful, inform smart card to clear the entries. 
    	// Not needed. See note below above the function
    	//status = clearLogs();
    	
    	// verify that the balance in the smart card
    	// matches the balance in the database.
    	//status = verifyBalance(card);
    	if (!status){
    		System.out.println("Card is corrupted.");
    		// REVOKE CARD.
    		revoke();
    		System.exit(1);
    	}    	
    	
    	// calculate new balance. 
    	short new_balance = (short) (card.balance + this.MONTHLY_ALLOWANCE); 
    
    	// perform an atomic operation of updating the 
    	// balance and storing the signatures to the database.
    	status = updateBalance(card, new_balance);
    	if (!status){
    		System.out.println("Updating balance failed.");
    	}
    	else
    		System.out.println("Card is charged.");
    }
}