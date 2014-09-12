package ru.hwsec.teamara;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import javacard.framework.AID;

import com.licel.jcardsim.base.Simulator;

public class CryptoTest {

	private static final String message = "TeamARA";
	
	public static void main(String[] args) {
		byte[] appletAID = { (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, (byte) 0x01 };
		AID aidInstance = new AID(appletAID, (short)0, (byte)appletAID.length);
		Simulator simulator = new Simulator();
		AID someaid = simulator.installApplet(aidInstance, CryptoTestApplet.class);
		if (simulator.selectApplet(someaid)) {
			byte[] respBytes = simulator.transmitCommand(new CommandAPDU(0, 0, 0, 0, message.getBytes().length).getBytes());
			String data = new String(new ResponseAPDU(respBytes).getData());
			if (data.equals(message))
				System.out.println("OK -> " + data);
			else
				System.out.println("Not OK -> " + data);
		} else
			System.out.println("Could not select applet.");
	}
}
