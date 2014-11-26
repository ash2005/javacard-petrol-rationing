package ru.hwsec.teamara;

import javax.smartcardio.CardException;



public class ChargingTerminal extends Terminal {

	/* Charging terminal is online and has access to the database. */
	private MySql db;
	
	public ChargingTerminal(MySql tdb){
        super();
        this.db = tdb;
    }

    /* Reference sec 7.6 of Design Document
     * Get card logs and ask card to clear logs
     */
    boolean getLogs(){
        return true;
    }



    /* Reference sec 7.6 of Design Document
     * Check if the card logs fulfil specified criteria
     *  - less than 200 litres per month
     *  - corresponds with backend
     *  - Only 5 withdrawals
     */
    boolean checkLogs(){
        return true;
    }


    /* Revoke the card if backend database has revoke flag set for that card*/
    //abstract boolean revoke();

    /* If no error, update the card balance.
     * Store updated balance in database */
    boolean updateBalance(){
    	return true;
    }
    
    void use (){
    	boolean status = true;
    	// Connect to the card.
    	
    	status = getLogs();
    	if (!status){
    		System.out.println("Getting logs failed.");
    		System.exit(1);
    	}
    		
    	status = updateBalance();
    	if (!status){
    		System.out.println("Updating balance failed.");
    		System.exit(1);
    	}    	

    }

}
