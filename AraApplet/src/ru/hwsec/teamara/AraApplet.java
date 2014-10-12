/**
 * 
 */
package ru.hwsec.teamara;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * @author javacard
 *
 */
public class AraApplet extends Applet {
	
	public AraApplet() {
        this.register();
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new AraApplet();
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();
		switch (buffer[ISO7816.OFFSET_INS]) {
		
		case (byte) 0x0a:
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) 5);	
			buffer[0] = (byte)0x03;
			buffer[1] = (byte)0x04;
			buffer[2] = (byte)0x05;
			buffer[3] = (byte)0x06;
			buffer[4] = (byte)0x07;
        	apdu.sendBytes((short) 0, (short) 5);
			break;
			
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}