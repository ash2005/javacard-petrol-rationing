package ru.hwsec.teamara;

public class PersonalisationTerminal {
	
	/* Personalisation terminal is online and has access to the database. */
	private MySql db;
	
	public PersonalisationTerminal(MySql tdb){
        this.db = tdb;
    }
	
	public boolean issueCard() {
		byte[] cardPrivateKey = {};
		byte[] cardPublicKey = {};
		byte[] cardPin = {};
		
		
		
		return true;
	}

}
