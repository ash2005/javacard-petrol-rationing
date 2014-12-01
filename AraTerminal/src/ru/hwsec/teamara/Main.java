package ru.hwsec.teamara;

public class Main {

	public static void main(String[] args) {
		MySql db = new MySql();
		db.initializedb();
		
		ChargingTerminal charging = new ChargingTerminal(db, (byte)0x21);
		charging.connectToCard();
		charging.use();
		
		PetrolTerminal pumping = new PetrolTerminal((byte) 0x11);
		pumping.use();
		pumping.use();
		pumping.use();
		charging.use();
		/*
		short new_balance = 200;
		byte [] balance = new byte[2];
		balance[0] = (byte)(new_balance);
		balance[1] = (byte)((new_balance >> 8) & 0xFF);
		
		
		new_balance = (short) ((balance[1] << 8) + (balance[0]&0xFF));
		System.out.println("Alvin:Test");
		System.out.println(new_balance);*/
	}

}
