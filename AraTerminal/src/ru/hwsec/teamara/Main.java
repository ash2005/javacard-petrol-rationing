package ru.hwsec.teamara;

public class Main {

	public static void main(String[] args) {
		MySql db = new MySql();
		db.initializedb();
		
		System.out.println("=========Charging Terminal==========");
		ChargingTerminal charging = new ChargingTerminal(db, (byte)0x21);
		if (charging.connectToCard())
			charging.use();
		
		
		System.out.println("=========Pumping Terminal==========");
		PetrolTerminal pumping = new PetrolTerminal((byte) 0x11);
		if (pumping.connectToCard())
			pumping.use();
		
		
		System.out.println("=========Pumping Terminal==========");
		if (pumping.connectToCard())
			pumping.use();


		System.out.println("=========Charging Terminal==========");
		if (charging.connectToCard())
			charging.use();
	}

}
