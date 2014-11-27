package ru.hwsec.teamara;

import javax.smartcardio.CardException;



public class ChargingTerminal extends AraTerminal {

	/*
	 * Class used to represent the card that it is used at the moment.
	 */
	public class Card {
		public int cardID;
		public short balance;
		public Card(){
			
		}
		public Card(int cardID, short balance) {
			super();
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
	private Card getLogs(){
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
    	card.balance = (short) 10; // According to the last log.
    	
    	// extract balance from last log entry.
    	
    	
        return card;
    }

	/*
	 * Compare the cardID's balance at the smart card and at the database.
	 */
	private boolean verify_balance(Card card){
		int tbalance = db.get_balance(card.cardID);
		if (tbalance == card.balance)
			return true;
		else
			return false;
	}
	
    /* Revoke the card if backend database has revoke flag set for that card*/
    boolean revoke(){
    	return true;
    }

    /* If no error, update the card balance.
     * Store updated balance in database */
    boolean updateBalance(){
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
    	
    	

    	status = updateBalance();
    	if (!status){
    		System.out.println("Updating balance failed.");
    		System.exit(1);
    	}    	

    }

}
