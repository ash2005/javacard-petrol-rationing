package ru.hwsec.teamara;

public class PersonalisationTerminal {
	
	/* Personalisation terminal is online and has access to the database. */
	private MySql db;
	
	public PersonalisationTerminal(MySql tdb){
        this.db = tdb;
    }
	
	public boolean create_user(){
		/*
		 * - Two PKI certificates, one each for key exchange and digital signature, 
		 * signed by the Intermediate Cards Certificate Authority (CA).
		 * - The corresponding private keys
		 * - LOAD Intermediate Pump CA and Intermediate Charging CA
		 * - Generated secret PIN and update
		 */
		
		
		return true;
	}

}
