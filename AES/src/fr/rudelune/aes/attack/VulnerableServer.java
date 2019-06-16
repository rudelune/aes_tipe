package fr.rudelune.aes.attack;

import javax.crypto.BadPaddingException;

import fr.rudelune.aes.Crypt;
import fr.rudelune.aes.Decrypt;
import fr.rudelune.aes.Key;

/**
 * @author rudelune
 */
public class VulnerableServer {

	private Key key;

	public byte[] run(Key key, byte[] msg) {
		this.key = key;
		return Crypt.crypt(msg, key);
	}

	boolean decrypt(byte[] iv, byte[] msg) {
		try {
			key.changeIV(iv);
			Decrypt.decrypt(msg, key);
			return true;
		} catch (BadPaddingException e) {
			return false;
		}
	}

}
