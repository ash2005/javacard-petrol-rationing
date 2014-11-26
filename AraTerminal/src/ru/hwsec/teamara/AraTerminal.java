package ru.hwsec.teamara;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Calendar;
import java.util.Random;
import java.util.Scanner;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class AraTerminal {

    private byte[] PUBLIC_KEY_BYTES = new byte[]{
        (byte)0x04, (byte)0x01, (byte)0x96, (byte)0x96, (byte)0x64, (byte)0x3a, (byte)0x14, (byte)0xda, (byte)0xe5, (byte)0x7c, (byte)0x15, (byte)0x83, (byte)0x6b, (byte)0x48, (byte)0x6f,
        (byte)0x83, (byte)0xac, (byte)0x4f, (byte)0x36, (byte)0x0a, (byte)0x47, (byte)0x9d, (byte)0x4b, (byte)0x9d, (byte)0x3e, (byte)0x85, (byte)0x01, (byte)0xd1, (byte)0x2d, (byte)0xf9,
        (byte)0x13, (byte)0x3a, (byte)0x70, (byte)0xee, (byte)0x9b, (byte)0xbb, (byte)0x58, (byte)0x65, (byte)0xc2, (byte)0x3d, (byte)0x29, (byte)0x9f, (byte)0xdb, (byte)0x54, (byte)0xac,
        (byte)0x2f, (byte)0x11, (byte)0x52, (byte)0x63, (byte)0xf2, (byte)0x9a
    };

    private byte[] PRIVATE_KEY_BYTES = new byte[]{
        (byte)0x00, (byte)0xf1, (byte)0xaf, (byte)0x06, (byte)0xac, (byte)0xa7, (byte)0x0d, (byte)0xf8, (byte)0x3f, (byte)0x89, (byte)0xd8, (byte)0x96, (byte)0x57, (byte)0x72, (byte)0x7d,
        (byte)0x93, (byte)0x79, (byte)0x1a, (byte)0xe8, (byte)0x76, (byte)0x7d, (byte)0xac, (byte)0x98, (byte)0x25, (byte)0x99
    };

    private byte[] SIGNATURE_BYTES = new byte[]{
        (byte)0x30, (byte)0x34, (byte)0x02, (byte)0x18, (byte)0x0c, (byte)0x4f, (byte)0xa8, (byte)0xdf, (byte)0x6f, (byte)0xd2, (byte)0x43, (byte)0x15, (byte)0xd3, (byte)0xf6, (byte)0xaa,
        (byte)0xb0, (byte)0xbd, (byte)0x34, (byte)0x6a, (byte)0x35, (byte)0x2a, (byte)0x9b, (byte)0xd7, (byte)0xb4, (byte)0x35, (byte)0x3e, (byte)0xbe, (byte)0x50, (byte)0x02, (byte)0x18,
        (byte)0x7f, (byte)0xa1, (byte)0x6a, (byte)0xd5, (byte)0x00, (byte)0x94, (byte)0xd2, (byte)0x90, (byte)0xa5, (byte)0xb4, (byte)0x6f, (byte)0xe3, (byte)0x85, (byte)0x7b, (byte)0xc8,
        (byte)0x48, (byte)0xcd, (byte)0xc8, (byte)0x03, (byte)0xc0, (byte)0x05, (byte)0x02, (byte)0xed, (byte)0x8f
    };

    private CardComm cardComm;

    private void execute() {
        /* INITIALISATION STATE */
        /*
        this.setPIN();
        this.pinCheck();
        this.pinCheck();
        */

        /* Issued State */
        try {
			this.performHandshake();
		} catch (CardException e) {
			System.out.println("Could not perform the handshake with the card.");
		}
    }


    /* Mutual Authentication Functions */

    private void performHandshake() throws CardException {
        ResponseAPDU resp;
        // We first generate 4 random bytes to send the card
        Random rnd = new Random(Calendar.getInstance().getTimeInMillis());
        byte[] termRndBytes = new byte[4];
        rnd.nextBytes(termRndBytes);

        // Send TERMINAL_HELLO and get back the CARD_HELLO answer containing 4 random bytes
        resp = this.cardComm.sendToCard(new CommandAPDU(0, Instruction.TERMINAL_HELLO, 0, 0, termRndBytes));
        byte[] cardRndBytes = resp.getData();
        System.out.println(cardRndBytes.length);

        // Send the public key of the terminal with the signature
        // 51 bytes (0..50) public key of the terminal
        // 54 bytes (51..104) signature of the key
        // Total: 105 bytes
        byte[] signedKey = new byte[105];
        System.arraycopy(PUBLIC_KEY_BYTES, 0, signedKey, 0, PUBLIC_KEY_BYTES.length);
        System.arraycopy(SIGNATURE_BYTES, 0, signedKey, PUBLIC_KEY_BYTES.length, SIGNATURE_BYTES.length);
        // P1 specifies what type of terminal this is:
        // P1 = 1 ==> charging terminal
        // P1 = 2 ==> pump terminal
        resp = this.cardComm.sendToCard(new CommandAPDU(0, Instruction.TERMINAL_KEY, 1, 0, signedKey));
        byte[] data = resp.getData();

        // Verify the public key and signature received from the card
        byte[] cardKeyBytes = new byte[51];
        byte[] cardSignatureBytes = new byte[54];
        System.arraycopy(data, 0, cardKeyBytes, 0, 51);
        System.arraycopy(data, 51, cardSignatureBytes, 0, 54);
        try {
			System.out.println(ECCTerminal.verifyCardKey(cardKeyBytes, cardSignatureBytes));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidParameterSpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Generate DH Secret
        resp = this.cardComm.sendToCard(new CommandAPDU(0, Instruction.GEN_SHARED_SECRET, 1, 0));
        byte[] cardSecret = resp.getData();
		System.out.printf("The DH Secret generated by the card is of byte length: ");
		System.out.println(cardSecret.length);
		if (cardSecret.length == 1){
			System.out.println(String.format("0x%02X", cardSecret[0]));
		}

    }

    /* PIN Functions */

    public void setPIN() throws CardException {
    	System.out.print("INITIALISATION: Please choose a strong PIN Code");
    	byte pincode[] = ask_for_PIN();

        ResponseAPDU resp;
        resp = this.cardComm.sendToCard(new CommandAPDU(0, Instruction.SET_PIN, 0, 0, pincode));
        /*
        byte[] cardRndBytes = resp.getData();
        System.out.println(cardRndBytes.length);

        for (byte b :  cardRndBytes)
        	System.out.format("0x%x ", b);
        System.out.println();
        */
    }

    public boolean pinCheck() throws CardException{
    	byte pincode[] = ask_for_PIN();
        ResponseAPDU resp;
        // Send TERMINAL_HELLO and get back the CARD_HELLO answer containing 4 random bytes
        resp = this.cardComm.sendToCard(new CommandAPDU(0, Instruction.CHECK_PIN, 0, 0, pincode));
        byte[] cardRndBytes = resp.getData();
        /*System.out.println(cardRndBytes.length);
        for (byte b :  cardRndBytes)
        	System.out.format("0x%x ", b);
        System.out.println();*/
        if(cardRndBytes[0] == 0x01)
        		System.out.println("Correct PIN");
        else{
        		System.out.println("Wrong PIN");
        		System.out.printf("Tries Remaining: ");
        		System.out.println(cardRndBytes[1]);
        }
        return true;
    }


    // Asks user for PIN and returns the byte array.
    private byte [] ask_for_PIN(){
    	String input = null;
    	byte[] bytes = ByteBuffer.allocate(4).putInt(1111).array(); // initialize

        System.out.println("");
        System.out.print("Enter PIN: ");
        Scanner in = new Scanner( System.in );

        try{
        	input = in.next();
        	int pin = Integer.parseInt(input); // Just to check if it is an integer, var is not used.


        	int i = 0;
        	for(char charUserOutput : String.valueOf(input).toCharArray())
        	{
            	 bytes[i] = (byte) charUserOutput;
            	 i++;
        	}
        	/*
            for (byte b : bytes)
            {
            	System.out.format("0x%x ", b);
            }
            System.out.println();
            */

        } catch(NumberFormatException e) {
        	System.out.println("Input is not a number");
        	System.exit(1);
        } catch (Exception e) {
            System.out.println("IO error.");
            System.exit(1);
        }
        return bytes;
    }

    public static void main(String[] arg) {
    	AraTerminal araTerminal = new AraTerminal();
        try {
			araTerminal.cardComm = new CardComm(true);
		} catch (CardException e) {
			System.out.println("Could not connect to the card or simulator.");
		}
    	araTerminal.execute();
    }
}
