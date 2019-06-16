package fr.rudelune.aes.attack;

import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

import fr.rudelune.aes.Key;
import fr.rudelune.aes.Util;

/**
 * @author rudelune
 */
public class AttackerClient {

	private final VulnerableServer	server;
	private int						decryptedMessagesSent	= 0;

	public AttackerClient(byte[] cipherText, Key publicKey, VulnerableServer server) {
		this.server = server;
		try {
			decrypt(cipherText, Util.convertByteMatrixToByteArray(publicKey.cloneIV()));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void decrypt(byte[] cipherText, byte[] iv) throws Exception {
		System.out.print("Message chiffré envoyé au serveur : \n");
		int nbBlocks = cipherText.length / 16;
		byte[] plaintext = new byte[cipherText.length];
		for (int i = nbBlocks - 1; i >= 0; i--) {
			byte[] common = Arrays.copyOfRange(cipherText, i * 16, (i + 1) * 16);
			if (i == 0) {
				System.arraycopy(decryptBlock(iv, common), 0, plaintext, i * 16, 16);
			} else {
				byte[] prevBlock = Arrays.copyOfRange(cipherText, (i - 1) * 16, i * 16);
				System.arraycopy(decryptBlock(prevBlock, common), 0, plaintext, i * 16, 16);
			}
			System.out.print('\n');
		}
		plaintext = Arrays.copyOf(plaintext, plaintext.length - plaintext[plaintext.length - 1]);
		System.out.println('\n' + new String(plaintext, "UTF-8"));
	}

	private byte[] decryptBlock(byte[] prevBlock, byte[] actualBlock) throws IllegalArgumentException {
		byte[] intermediate = new byte[16];
		byte[] plaintext = new byte[16];

		for (byte indexByte = 15; indexByte >= 0; indexByte--) {
			int paddingByte = 16 - indexByte;
			byte[] previousCipherText = new byte[16];
			for (int i = indexByte + 1; i < 16; i++) {
				previousCipherText[i] = (byte) (intermediate[i] ^ paddingByte);
			}
			byte lastByte = decryptByte(previousCipherText, actualBlock, indexByte);
			intermediate[indexByte] = (byte) (lastByte ^ paddingByte);
			plaintext[indexByte] = (byte) (intermediate[indexByte] ^ prevBlock[indexByte]);

		}
		return plaintext;
	}

	private byte decryptByte(byte[] prevBlock, byte[] actualBlock, byte indexByte) throws IllegalArgumentException {
		for (int actualByte = 0; actualByte <= 0xFF; actualByte++) {
			prevBlock[indexByte] = (byte) actualByte;
			if (testPadding(prevBlock, actualBlock)) {
				if (indexByte == 15) {
					prevBlock[14]++;
					if (testPadding(prevBlock, actualBlock)) {
						return (byte) actualByte;
					}
				} else {
					return (byte) actualByte;
				}
			}
		}
		throw new IllegalArgumentException("Pas de solution trouvée, message illégal !");
	}

	private boolean testPadding(byte[] prevBlock, byte[] actualBlock) {
		System.out.print(
				'\r' + DatatypeConverter.printHexBinary(prevBlock) + ", messages envoyés : " + ++decryptedMessagesSent);
		return server.decrypt(prevBlock, actualBlock);
	}

}
