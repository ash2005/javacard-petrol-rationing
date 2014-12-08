package ru.hwsec.teamara;

import java.security.GeneralSecurityException;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class ChargingTerminal extends AraTerminal {

	private MySql db;
	
	public ChargingTerminal(MySql tdb, byte termID) {
        super(termID, (byte)0x01);
        this.db = tdb;
    }

	private boolean getLogs(Card card) {
    	while(true) {
    		ResponseAPDU resp = null;
	        try {
	        	resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.GET_LOGS, 0, 0));
	            if(debug == true) {
	            	System.out.println("In function ChargingTerminal.getLogs");
	            	System.out.println("Contents of log response from card");
	            	for (byte b :  resp.getData())
	            		System.out.format("0x%x ", b);
	            	System.out.println();
	            }
			} catch (CardException ex) {
				System.out.println("Error occured in function ChargingTerminal.getLogs while sending APDU to the card");
			}
			
			if(resp.getData().length == 1 && resp.getData()[0] == (byte) 0xff) // signal that card log is empty
				break;
		
			byte dateBytes[] = new byte[Constants.Transaction.DATE_LENGTH]; 
			byte termSigBytes[] = new byte[Constants.Transaction.SIG_LENGTH];
			byte cardSigBytes[] = new byte[Constants.Transaction.SIG_LENGTH];
			byte[] log = resp.getData();
			
			int termID = log[0];
			short balance = (short)((log[Constants.Transaction.BALANCE_OFFSET + 1] << 8) + (log[Constants.Transaction.BALANCE_OFFSET] & 0xff));
			
			System.arraycopy(log, Constants.Transaction.DATE_OFFSET,     dateBytes,    0, Constants.Transaction.DATE_LENGTH);			
			System.arraycopy(log, Constants.Transaction.TERM_SIG_OFFSET, termSigBytes, 0, Constants.Transaction.SIG_LENGTH);
			System.arraycopy(log, Constants.Transaction.CARD_SIG_OFFSET, cardSigBytes, 0, Constants.Transaction.SIG_LENGTH);
			
			String date    = new String(dateBytes);
			String termSig = new sun.misc.BASE64Encoder().encode(termSigBytes);
			String cardSig = new sun.misc.BASE64Encoder().encode(cardSigBytes);
			
			boolean status = db.addlog(card.cardID, balance, (short)0, termID, date, cardSig, termSig);
	    	if(!status)
	    		System.out.println("In ChargingTerminal.getLogs an error occured while storing logs");
    	}
        return true;
    }
	
	/*
	 * Compare the cardID's balance at the smart card and at the database.
	 */
	
	private boolean verifyBalance(Card card) {
		int tbalance = db.get_balance(card.cardID);
		if(tbalance == card.balance)
			return true;
		else if (tbalance == -1)
			System.out.println("cardID: " + card.cardID + " has not been found.");
		else if (tbalance == -2)
			System.out.println("SQL error");		
		return false;
	}
	
    /*
     * Perform an atomic operation. TODO!!!
     * - Sign the message
     * - Send message and new balance to the smart card
     * - Get the signature
     * - Store the message and the signatures to the database
     */
	
    private boolean updateBalance(Card card, short newBalance){
    	byte[] messageBytes = new byte[Constants.Transaction.MSG_TOSIGN_LENGTH];
    	byte[] termSignatureBytes = null;
    	String currentDate = this.getDate();
		int dateLength = currentDate.getBytes().length;
		
		if(debug && dateLength != Constants.Transaction.DATE_LENGTH)
			System.out.println("In ChargingTerminal.updateBalance the length of the current date is wrong");
    	
		messageBytes[0] = this.termID;
		System.arraycopy(currentDate.getBytes(), 0, messageBytes, Constants.Transaction.DATE_OFFSET, Constants.Transaction.DATE_LENGTH);
		messageBytes[Constants.Transaction.BALANCE_OFFSET] = (byte)(newBalance);
		messageBytes[Constants.Transaction.BALANCE_OFFSET + 1] = (byte)((newBalance >> 8) & 0xff);
		
		try {
			termSignatureBytes = ECCTerminal.performSignature(messageBytes);
		} catch (GeneralSecurityException e) {
			System.out.println("In ChargingTerminal.updateBalance a crypto exception occured");
		}
		
		byte[] cardSignatureBytes = new byte[Constants.Transaction.SIG_LENGTH];
		try {
			ResponseAPDU resp = this.cardComm.sendToCard(new CommandAPDU(0, Constants.Instruction.UPDATE_BALANCE_CHARGE, 0, 0, messageBytes));
			cardSignatureBytes = resp.getData();
		} catch (CardException ex) {
			System.out.println("Getting logs failed.");
		}
		
		if(debug) {
			try{
				boolean validSig =  ECCTerminal.performSignatureVerification(messageBytes, cardSignatureBytes, super.cardKeyBytes);
				System.out.println("Signature received from card is valid: " + String.valueOf(validSig));	
			}
			catch (GeneralSecurityException e){
				System.out.println("Signature Verification Error");
			}
		}
		
		String cardSignature = new sun.misc.BASE64Encoder().encode(cardSignatureBytes);
		String termSignature = new sun.misc.BASE64Encoder().encode(termSignatureBytes);
    	db.addlog(card.cardID, card.balance, AraTerminal.MONTHLY_ALLOWANCE, this.termID, currentDate, cardSignature, termSignature);
    	db.updateBalance(card.cardID, newBalance);
    	db.charged(card.cardID);
    	return true;
    }
    
    void use() {
    	System.out.println("Welcome to charging terminal.");
    	
    	short balance = this.getBalance();
    	Card card = new Card(0xa1, balance);  
    	
    	// retrieve and store logs as well as get the basic info of the card.
    	boolean status = this.getLogs(card);
    	if (!status){
    		System.out.println("Card is corrupted.");
    		System.exit(1);
    	}    	
    	
    	if (db.charge(card.cardID) == false){
    		System.out.println("Card is already charged, exiting!");
    		System.exit(1);
    	}
    		
    	// calculate new balance. 
    	int newBalance = card.balance + AraTerminal.MONTHLY_ALLOWANCE; 
    	status = updateBalance(card, (short)newBalance);
    	if (!status)
    		System.out.println("Updating balance failed.");
    	else
    		System.out.println("Charging completed!");
    	System.out.println();
    	System.out.println();
    }
    
    /*
	 * Class used to represent the card that it is used at the moment.
	 */
    
	public static class Card {
		protected int cardID;
		protected short balance;
		
		public Card() { }
		
		public Card(int cardID, short balance) {
			this.cardID = cardID;
			this.balance = balance;
		}
	}
}