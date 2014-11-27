/**
 * 
 */
package ru.hwsec.teamara;

/**
 * @author javacard
 *
 */
public class Main {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		MySql db = new MySql();
		db.initializedb();
		
		//PersonalisationTerminal issue = new PersonalisationTerminal(db);
		// updates the database with the new user.
		//issue.createuser(db);
		
		//PetrolTerminal pumping = new PetrolTerminal();
		//pumping.use();
		
		ChargingTerminal charging = new ChargingTerminal(db, (byte) 0x01);
		//charging.use();
		
		
	}

}
