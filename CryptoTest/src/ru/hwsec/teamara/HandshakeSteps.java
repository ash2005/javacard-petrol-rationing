package ru.hwsec.teamara;

public enum HandshakeSteps {
	
	ZERO			((byte)0),		// no handshake actions have been performed
	RESET			((byte)1),		// instruct each other to start a new handshake from scratch
	PRE_HANDSHAKE	((byte)2),		// signal each other they are ready to start a new handshake
	
	HELLO			((byte)3),		// initial hello message which contains certificates
	CRYPTO			((byte)4),		// exchange of cryptographic material
	VERIFY			((byte)5),		// verify shared secret
	
	DONE			((byte)6);		// handshake has finished
	
	private byte code;
	
	private HandshakeSteps(byte code) {
		this.code = code;
	}
	
	public byte getCode() {
		return this.code;
	}
	
	public static HandshakeSteps fromCode(byte code) {
		for(HandshakeSteps hs : HandshakeSteps.values())
			if (hs.getCode() == code)
				return hs;
		return null;
	}
}
