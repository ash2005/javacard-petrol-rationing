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

		ChargingTerminal charging = new ChargingTerminal(db, (byte) 0x21);
		//charging.execute();
		charging.use();
		
		PetrolTerminal pumping = new PetrolTerminal( (byte) 0x11 );
		//pumping.execute();
		pumping.use();
		pumping.use();


		
	}

}
