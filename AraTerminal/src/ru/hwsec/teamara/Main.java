package ru.hwsec.teamara;

public class Main {

	public static void main(String[] args) {
		MySql db = new MySql();
		db.initializedb();
		
		
		ChargingTerminal charging = new ChargingTerminal(db, (byte)0x21);
		//if (charging.connectToCard())
			charging.use();
		
		PetrolTerminal pumping = new PetrolTerminal((byte) 0x11);
		//if (pumping.connectToCard()){
			pumping.use();
			pumping.use();
			pumping.use();
		//}
		
		
		//if (charging.connectToCard())
			charging.use();
	}

}
