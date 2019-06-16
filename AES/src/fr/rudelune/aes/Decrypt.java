package fr.rudelune.aes;

import static fr.rudelune.aes.AESConfig.Mode.*;
import static fr.rudelune.aes.AESConfig.Padding.*;

import javax.crypto.BadPaddingException;

/**
 * @author rudelune
 */
public class Decrypt {

	/**
	 * Déchiffrement d'une matrice 4*4 d'octets.
	 *
	 * @param array
	 *            Matrice de 4x4 octets à déchiffrer.
	 * @param keys
	 *            Ensemble des clés générées à partir d'une première.
	 * @return Matrice de 4*4 octets déchiffrée.
	 */
	private static byte[][] decrypt(byte[][] array, byte[][][] keys, boolean minsc) {
		byte[][] result;
		byte nbKeys = (byte) keys.length;
		if (!minsc) {
			result = Util.xor(array, keys[nbKeys - 1]);// dernier xor par la sous-clé
			result = Util.shift(result, true, false);// décalage des colonnes
			Util.replaceSBOX(result, true, false);// application de la SBOX
			result = Util.xor(result, keys[nbKeys - 2]);// application de la sous-clé
			for (byte i = (byte) (nbKeys - 3); i >= 0; i--) {
				result = GaloisMult.calc(result, Util.decryptMatrixAES);// Mixage des colonnes
				result = Util.shift(result, true, false);// décalage des colonnes
				Util.replaceSBOX(result, true, false);// application de la SBOX
				result = Util.xor(result, keys[i]);// application de la sous-clé ou clé pour le dernier tour
			}
			return result;
		} else {
			result = Util.xor(array, keys[nbKeys - 1]);
			result = Util.shift(result, false, true);
			Util.replaceSBOX(result, false, true);
			result = Util.xor(result, keys[nbKeys - 2]);
			for (byte i = (byte) (nbKeys - 3); i >= 0; i--) {
				result = GaloisMult.calc(result, Util.de_CryptMatrixMINSC);
				result = Util.shift(result, false, true);
				Util.replaceSBOX(result, false, true);
				result = Util.xor(result, keys[i]);
			}
			return result;
		}

	}

	/**
	 * Déchiffrement d'une liste d'octets.
	 *
	 * @param input
	 *            Liste d'octets à déchiffrer.
	 * @param key
	 *            Clé de déchiffrement contenant la configuration de l'algorithme et le vecteur d'initialisation.
	 * @return Liste d'octets déchiffrés.
	 * @throws BadPaddingException
	 *             Renvoie une exception si le remplissage (padding) n'est pas valide.
	 */
	public static byte[] decrypt(byte[] input, Key key) throws BadPaddingException {
		boolean minsc = key.getConfig().isMinsc();
		byte[][][] keyScheduled = key.getKeyScheduled();
		byte[] result = new byte[input.length];
		AESConfig.Mode mode = key.getConfig().getMode();

		byte[][] last = null;
		if (mode != ECB) {
			last = key.cloneIV();
		}

		byte[] buffer = new byte[16];
		for (int i = 0; i < input.length / 16; i++) {
			System.arraycopy(input, 16 * i, buffer, 0, 16);
			byte[][] array = Util.convertByteArrayToByteMatrix(buffer);

			if (mode == ECB)
				array = decrypt(array, keyScheduled, minsc);
			else if (mode == CBC) {
				byte[][] buf = Util.xor(last, decrypt(array, keyScheduled, minsc));
				last = array.clone();
				array = buf;
			} else if (mode == CFB) {
				byte[][] buf = Crypt.crypt(last, key);
				last = array.clone();
				array = buf;
				array = Util.xor(last, array);
			} else if (mode == OFB) {
				last = Crypt.crypt(last, key);
				array = Util.xor(last, array);
			}

			for (byte j = 0; j < 4; j++) {
				for (byte k = 0; k < 4; k++) {
					result[16 * i + 4 * j + k] = array[k][j];
				}
			}
		}
		return removePadding(result, key.getConfig());
	}

	/**
	 * Enlève le remplissage du message déchiffré.
	 *
	 * @param array
	 *            Message complété sous la forme d'un tableau d'octets.
	 * @param config
	 *            Configuration de l'algorithme utilisée.
	 * @return Message sous la forme 'un tableau d'octets.
	 * @throws BadPaddingException
	 *             Retourne une exception si le remplissage (padding) n'est pas valide.
	 */
	private static byte[] removePadding(byte[] array, AESConfig config) throws BadPaddingException {
		byte[] newArray;
		byte goal;
		int length = array.length;
		AESConfig.Padding padding = config.getPadding();
		if (padding == PKCS7) {
			goal = array[length - 1];
			if (goal < 1 || goal > 16) {
				throw new BadPaddingException();
			}
			for (byte i = 1; i < goal; i++) {
				if (array[length - 1 - i] != goal) {
					throw new BadPaddingException();
				}
			}
			newArray = new byte[length - goal];
			System.arraycopy(array, 0, newArray, 0, length - goal);
			return newArray;
		} else if (padding == ANSI_X923) {
			goal = array[length - 1];
			if (goal < 1 || goal > 16) {
				throw new BadPaddingException();
			}
			for (byte i = 1; i < goal; i++) {
				if (array[length - 1 - i] != 0) {
					throw new BadPaddingException();
				}
			}
			newArray = new byte[length - goal];
			System.arraycopy(array, 0, newArray, 0, length - goal);
			return newArray;
		} else if (padding == ISO_10126) {
			goal = array[length - 1];
			if (goal < 1 || goal > 16) {
				throw new BadPaddingException();
			}
			newArray = new byte[length - goal];
			System.arraycopy(array, 0, newArray, 0, length - goal);
			return newArray;
		} else if (padding == ISO_7816_4) {
			byte counter = 0;
			try {
				while (array[length - 1 - counter] == 0) {
					counter++;
				}
			} catch (ArrayIndexOutOfBoundsException e) {
				throw new BadPaddingException();
			}
			if (array[length - 1 - counter] != counter) {
				throw new BadPaddingException();
			}
			newArray = new byte[length - counter];
			System.arraycopy(array, 0, newArray, 0, length - counter - 1);
			return newArray;
		} else if (padding == ZERO_PAD) {
			byte counter = 0;
			while (length > counter && array[length - 1 - counter] == 0) {
				counter++;
			}
			if (length == counter)
				return new byte[0];
			newArray = new byte[length - counter];
			System.arraycopy(array, 0, newArray, 0, length - counter);
			return newArray;
		} else {
			return array;
		}
	}

}
