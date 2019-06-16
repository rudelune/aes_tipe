package fr.rudelune.aes;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.xml.bind.DatatypeConverter;

/**
 * @author rudelune
 */
class Main {

	public static void main(String[] args) throws IOException, BadPaddingException, InvalidKeyException {
		System.out.println("Ce programme a été développé par rudelune (rudelune) dans le cadre de son TIPE.");
		byte[][] mainKey;
		Scanner sc = new Scanner(System.in);

		System.out.println("Quel algorithme souhaitez-vous utiliser ?"
				+ "\n0 - AES (Advanced Encryption Standard) (choix par défaut)"
				+ "\n1 - MINSC (MINSC Is Not a Secured Cipher)");
		String inputStr = sc.nextLine();
		boolean minsc = inputStr.equals("1");

		AESConfig.Mode mode = AESConfig.Mode.ECB;

		if (!minsc) {
			System.out.println("- Quelle méthode de chiffrement souhaitez-vous utiliser ?"
					+ "\n0 - ECB (Electronic Codebook)" + "\n1 - CBC (Cipher Block Chaining) (choix par défaut)"
					+ "\n2 - CFB (Cipher FeedBack)" + "\n3 - OFB (Output FeedBack)");
			inputStr = sc.nextLine();

			if (inputStr.equals("")) {
				mode = AESConfig.Mode.CBC;
			} else {
				mode = AESConfig.Mode.values()[Integer.parseInt(inputStr)];
			}
		}

		System.out.println("\n- Veuillez entrer votre clé en hexadécimal : (ex : 2b28ab097eaef7cf15d2154f16a6883c)."
				+ "\n- Entrez 0 pour qu'on vous en choisisse une au hasard de 128 bits, 1 pour une de 192 bits"
				+ " et 2 pour une de 256 bits (choix par défaut).");
		String keyString = sc.nextLine();
		if (keyString.equals("")) {
			keyString = "2";
		}
		if (keyString.equals("0") || keyString.equals("1") || keyString.equals("2")) {
			System.out.println("Votre clé aléatoire est :");
			keyString = Util.displayByteMatrix(
					Util.generateRandomByteMatrix(keyString.equals("0") ? 4 : (keyString.equals("1") ? 6 : 8)));
		}
		mainKey = Util.convertStrToByteMatrix(keyString);
		AESConfig.KeyLength keyLength = mainKey[0].length == 4 ? AESConfig.KeyLength.AES128
				: (mainKey[0].length == 6 ? AESConfig.KeyLength.AES192 : AESConfig.KeyLength.AES256);

		System.out.println("\n- Quel padding souhaitez-vous utiliser ?" + "\n0 - Standard PCKS7 (choix par défaut)"
				+ "\n1 - Norme ANSI X.923" + "\n2 - Norme ISO 10126" + "\n3 - Norme ISO/IEC 7816-4 "
				+ "\n4 - Zero padding (peu recommandé pour les fichiers binaires)");
		inputStr = sc.nextLine();
		AESConfig.Padding padding;
		if (inputStr.equals("")) {
			padding = AESConfig.Padding.PKCS7;
		} else {
			padding = AESConfig.Padding.values()[Integer.parseInt(inputStr)];
		}

		Key key = new Key(new AESConfig(mode, padding, keyLength, minsc), mainKey);

		System.out.println("\n- Vous souhaitez chiffrer :" + "\n0 - Un message (UTF-8) (Choix par défaut)"
				+ "\n1 - Un message binaire (en hexadécimal)" + "\n2 - Une image");
		inputStr = sc.nextLine();
		byte format = 0;
		if (!inputStr.equals("")) {
			format = Byte.parseByte(inputStr);
		}

		if (format == 0) {
			System.out.println("- Veuillez entrer votre message :");
			byte[] msg = sc.nextLine().getBytes(StandardCharsets.UTF_8);
			long time = System.nanoTime();
			byte[] result = Crypt.crypt(msg, key);
			System.out.println("- Chiffrage en " + (System.nanoTime() - time) / 1000000 + " ms :");
			System.out.println(Util.getByteArrayAsNumber(result));
			System.out.println("----------------------");
			time = System.nanoTime();
			result = Decrypt.decrypt(result, key);
			System.out.println("- Déchiffrage en " + (System.nanoTime() - time) / 1000000 + " ms :");
			System.out.println(new String(result, StandardCharsets.UTF_8));
		} else if (format == 1) {
			System.out.println("- Veuillez entrer votre message :");
			byte[] bytes = DatatypeConverter.parseHexBinary(sc.nextLine());
			long time = System.nanoTime();
			byte[] result = Crypt.crypt(bytes, key);
			System.out.println("- Chiffrage en " + (System.nanoTime() - time) / 1000000 + " ms :");
			System.out.println(Util.getByteArrayAsNumber(result));
			System.out.println("----------------------");
			time = System.nanoTime();
			result = Decrypt.decrypt(result, key);
			System.out.println("- Déchiffrage en " + (System.nanoTime() - time) / 1000000 + " ms :");
			System.out.println(Util.getByteArrayAsNumber(result));
		} else if (format == 2) {
			System.out.println("- Veuillez entrer le chemin du fichier :");
			ImageLoader image = new ImageLoader(sc.nextLine());
			long time = System.nanoTime();
			image.crypt(key);
			System.out.println("- Chiffrage en " + (System.nanoTime() - time) / 1000000 + " ms :");
			image.save("crypted_");
			System.out.println("----------------------");
			time = System.nanoTime();
			image.decrypt(key);
			System.out.println("- Déchiffrage en " + (System.nanoTime() - time) / 1000000 + " ms :");
		}
	}

}
