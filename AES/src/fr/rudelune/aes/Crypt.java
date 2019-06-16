package fr.rudelune.aes;

import static fr.rudelune.aes.AESConfig.Mode.*;
import static fr.rudelune.aes.AESConfig.Padding.*;

import java.util.Random;

/**
 * @author rudelune
 */
public class Crypt {

	/**
	 * Chiffrement d'une matrice 4*4 octets.
	 *
	 * @param block
	 *            Matrice de 4x4 octets représentant le bloc à chiffrer.
	 * @param key
	 *            Clé de chiffrement.
	 * @return Matrice de 4*4 octets chiffrés.
	 */
	static byte[][] crypt(byte[][] block, Key key) {
		byte[][] result;
		boolean minsc = key.getConfig().isMinsc();
		byte[][][] keyScheduled = key.getKeyScheduled();// génération des sous-clés
		int nbRounds = keyScheduled.length;
		result = Util.xor(block, keyScheduled[0]);// 1er xor par la clé

		for (byte i = 1; i < nbRounds; i++) {
			Util.replaceSBOX(result, false, minsc);// application de la SBOX
			result = Util.shift(result, false, minsc);// décalage des colonnes
			if (i < nbRounds - 1) {
				result = GaloisMult.calc(result, (minsc ? Util.de_CryptMatrixMINSC : Util.cryptMatrixAES));
				// Mixage des colonnes
			}
			result = Util.xor(result, keyScheduled[i]);// application de la sous-clé
		}
		return result;
	}

	/**
	 * Chiffrement d'une liste d'octets.
	 *
	 * @param input
	 *            Liste d'octets à chiffrer.
	 * @param key
	 *            Clé avec le mode de chiffrement et le vecteur d'initialisation.
	 * @return Liste d'octets chiffrés.
	 */
	public static byte[] crypt(byte[] input, Key key) {
		AESConfig.Mode mode = key.getConfig().getMode();
		byte[] result;
		result = addPadding(input, key.getConfig());

		byte[][] last = null;
		if (mode != ECB) {
			last = key.cloneIV();
		}

		byte[] buffer = new byte[16];
		for (int i = 0; i < result.length / 16; i++) {
			System.arraycopy(result, 16 * i, buffer, 0, 16);
			byte[][] array = Util.convertByteArrayToByteMatrix(buffer);

			if (mode == ECB)
				array = crypt(array, key);
			else if (mode == CBC)
				array = crypt(Util.xor(last, array), key);
			else if (mode == CFB)
				array = Util.xor(crypt(last, key), key.getMainKey());
			else if (mode == OFB) {
				last = crypt(last, key);
				array = Util.xor(last, array);
			}

			for (byte j = 0; j < 4; j++) {
				for (byte k = 0; k < 4; k++) {
					result[16 * i + 4 * j + k] = array[k][j];
				}
			}
			if (mode != ECB && mode != OFB)
				last = array;
		}
		return result;
	}

	/**
	 * Complète un message pour que sa taille soit compatible avec l'algorithme.
	 *
	 * @param array
	 *            Message sous la forme d'un tableau d'octets.
	 * @param config
	 *            Configuration du chiffrement utilisée.
	 * @return Message complété sous la forme d'un tableau d'octets.
	 */
	private static byte[] addPadding(byte[] array, AESConfig config) {
		byte[] paddingBytes = getPaddingToAdd(array.length, config);
		if (paddingBytes != null && paddingBytes.length > 0) {
			byte[] newArray = new byte[array.length + paddingBytes.length];
			System.arraycopy(array, 0, newArray, 0, array.length);
			System.arraycopy(paddingBytes, 0, newArray, array.length, paddingBytes.length);
			return newArray;
		}
		return array;
	}

	/**
	 * Retourne le message à ajouter à l'original pour le compléter.
	 *
	 * @param length
	 *            Nombre d'octets du message original.
	 * @param config
	 *            Configuration du chiffrement utilisée.
	 * @return Message à ajouter à l'original pour qu'il fasse une taille valide.
	 */
	private static byte[] getPaddingToAdd(int length, AESConfig config) {
		int rest = length % 16;
		byte enhanceSize = (byte) (16 - rest);
		byte[] paddingBytes = null;
		AESConfig.Padding padding = config.getPadding();
		if (padding == PKCS7) {
			paddingBytes = new byte[enhanceSize];
			for (int i = 0; i < enhanceSize; i++) {
				paddingBytes[i] = enhanceSize;
			}
		} else if (padding == ANSI_X923) {
			paddingBytes = new byte[enhanceSize];
			paddingBytes[enhanceSize - 1] = enhanceSize;
		} else if (padding == ISO_10126) {
			paddingBytes = new byte[enhanceSize];
			Random random = new Random();
			for (int i = 0; i < enhanceSize - 1; i++) {
				paddingBytes[i] = (byte) random.nextInt(0x100);
			}
			paddingBytes[enhanceSize - 1] = enhanceSize;
		} else if (padding == ISO_7816_4) {
			paddingBytes = new byte[enhanceSize];
			paddingBytes[0] = enhanceSize;
		} else if (padding == ZERO_PAD) {
			paddingBytes = new byte[enhanceSize];
		}
		return paddingBytes;
	}

}
