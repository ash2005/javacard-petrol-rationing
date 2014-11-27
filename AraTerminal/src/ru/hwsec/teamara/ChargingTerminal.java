package ru.hwsec.teamara;

import javax.smartcardio.CardException;



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

    /* 
     * Reference sec 7.6 of Design Document
     * Get card logs and ask card to clear logs
     * 
     * Additionally,    TODO OR REMOVE.
     * Check if the card logs fulfil specified criteria
     *  - less than 200 litres per month
     *  - Only 5 withdrawals
     */
	//private Card getLogs(){
	public Card getLogs(){ // for testing.
    	boolean status = false;
    	Card card = new Card();
    	// For any entry
    	
    	// cardID, balance, transaction, termID, DATE, sig_card, sig_term
    	//Entry new_entry = 
    	status = db.addlog(1001, (short) 10, (short) -50, 2001, "2014-11-27 15:01:35", "sig_card", "sig_term" );
    	if (!status){
    		System.out.println("Getting logs failed.");
    		System.exit(1);
    	}
    	card.cardID = 1001;
    	card.balance = (short) 250; // According to the last log.
    	
    	// extract balance from last log entry.
    	
    	
    	System.out.println(verify_balance(card));
        return card;
    }

	/*
	 * Compare the cardID's balance at the smart card and at the database.
	 */
	private boolean verify_balance(Card card){
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

    /*
     * Perform an atomic operation. TODO!!!
     * - Sign the message
     * - Send message and new balance to the smart card
     * - Get the signature
     * - Store the message and the signatures to the database
     */
    private boolean updateBalance(Card card, int new_balance, String msg){
    	// Create signature.
    	byte[] sig_term_bytes = ECCTerminal.performSignatureTerminal(msg);
    	String sig_term = new sun.misc.BASE64Encoder().encode(sig_term_bytes);
    	
    	// Send new balance and msg to the smart card and get the signature.
    	byte[] sig_card_bytes = {(byte) 0x01, (byte) 0x01}; // testing
    	String sig_card = new sun.misc.BASE64Encoder().encode(sig_card_bytes);
    	
    	// Verify signature of smart card.
    	//TODO
    	
    	// Save log entry in the database.
    	db.addlog(card.cardID, card.balance, this.MONTHLY_ALLOWANCE, (int) this.termID, this.get_date(), sig_card, sig_term);
    	
    	// Update balance in table sara_card
    	db.updateBalance(card.cardID, new_balance);
    	
    	return true;
    }
    
    void use (){
    	boolean status = true;
    	short tbalance = 0;
    	
    	// Connect to the card.

    	Card card = getLogs();

    	status = verify_balance(card);
    	if (!status){
    		//System.out.println("Balance is not valid."); // if debug
    		System.out.println("Card is corrupted.");
    		// REVOKE CARD.
    		revoke();
    		System.exit(1);
    	}    	
    	
    	// Calculate new balance. 
    	short new_balance = (short) (card.balance + this.MONTHLY_ALLOWANCE); 
    	
    	// Construct the message that has to be signed by both the terminal and the smart card.
    	String msg = Integer.toString(this.termID) +  Integer.toString(new_balance) + this.get_date();
    	
    	status = updateBalance(card, new_balance, msg);
    	if (!status){
    		System.out.println("Updating balance failed.");
    		System.exit(1);
    	}    	

    }

}
