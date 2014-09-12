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
public class CryptoTestApplet extends Applet {
	
	private static final byte[] message = "TeamARA".getBytes();
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new CryptoTestApplet();
	}
	
	public CryptoTestApplet() {
		this.register();
	}

	public void process(APDU apdu) {
		// Good practice: Return 9000 on SELECT
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS]) {
		case (byte) 0x00:
			Util.arrayCopy(message, (short)0, buf, (short)0, (short)message.length);
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)message.length);
			apdu.sendBytes((short)0, (short)message.length);
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}