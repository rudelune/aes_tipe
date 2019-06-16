package fr.rudelune.aes;

import static fr.rudelune.aes.AESConfig.KeyLength.AES128;
import static fr.rudelune.aes.AESConfig.KeyLength.AES192;

/**
 * @author rudelune
 */
class AESConfig {

	private final Mode		mode;
	private final Padding	padding;
	private final KeyLength	keyLength;
	private final boolean	minsc;

	/**
	 * Défini le mode utilisé pour chiffrer.
	 *
	 * @param mode
	 *            Mode d'opération.
	 * @param padding
	 *            Mode de remplissage (padding).
	 * @param keyLength
	 *            Taille de la clé.
	 * @param minsc
	 *            Est-ce que l'algorithme MINSC est utilisé.
	 */
	AESConfig(Mode mode, Padding padding, KeyLength keyLength, boolean minsc) {
		this.mode = mode;
		this.padding = padding;
		this.keyLength = keyLength;
		this.minsc = minsc;
	}

	/**
	 * Renvoie le mode de chiffrement utilisé.
	 *
	 * @return Mode de chiffrement utilisé.
	 */
	Mode getMode() {
		return mode;
	}

	/**
	 * Renvoie le padding utilisé.
	 *
	 * @return Padding utilisé.
	 */
	Padding getPadding() {
		return padding;
	}

	/**
	 * Génère une clé aléatoirement de la taille indiquée par la configuration.
	 *
	 * @return La clé aléatoire.
	 */
	byte[][] generateKey() {
		return Util.generateRandomByteMatrix(keyLength == AES128 ? 4 : (keyLength == AES192 ? 6 : 8));
	}

	/**
	 * @return Est-ce que le mode de chiffrement choisi à besoin d'un vecteur d'initialisation.
	 */
	boolean needIV() {
		return mode.needIV();
	}

	/**
	 * @return Est-ce que l'algorithme de chiffrement utilisé est Minsc.
	 */
	boolean isMinsc() {
		return minsc;
	}

	KeyLength getKeyLength() {
		return keyLength;
	}

	public enum Mode {

		/**
		 * Electronic CodeBook
		 */
		ECB,

		/**
		 * Cipher Block Chaining
		 */
		CBC,

		/**
		 * Cipher FeedBack
		 */
		CFB,
		/**
		 * Output FeedBack
		 */
		OFB;

		/**
		 * @return Est-ce que le mode de chiffrement choisi à besoin d'un vecteur d'initialisation.
		 */
		public boolean needIV() {
			return this != ECB;
		}

	}

	public enum Padding {

		/**
		 * Consiste à ajouter le nombre d'octets manquants, chacun ayant comme valeur le nombre d'octets manquants.
		 */
		PKCS7,

		/**
		 * Consiste à ajouter des 0 puis pour le dernier octet manquant, à mettre un octet ayant comme valeur le nombre
		 * d'octets ayant été nécessaires pour compléter le message.
		 */
		ANSI_X923,

		/**
		 * Consiste à ajouter des octets aléatoires puis pour le dernier octet manquant, à mettre un octet ayant comme
		 * valeur le nombre d'octets ayant été nécessaires pour compléter le message.
		 */
		ISO_10126,

		/**
		 * Consiste à mettre un octet ayant comme valeur le nombre d'octets manquants puis à compléter avec des 0.
		 */
		ISO_7816_4,

		/**
		 * Consiste à compléter le message avec des 0.
		 */
		ZERO_PAD

	}

	public enum KeyLength {

		/**
		 * Taille de la clé = 128 bits.
		 */
		AES128((byte) 10, (byte) 11),

		/**
		 * Taille de la clé = 192 bits.
		 */
		AES192((byte) 8, (byte) 13),

		/**
		 * Taille de la clé = 256 bits.
		 */
		AES256((byte) 7, (byte) 15);

		private final byte	nbRounds;
		private final byte	nbKeys;

		KeyLength(byte nbRounds, byte nbKeys) {
			this.nbRounds = nbRounds;
			this.nbKeys = nbKeys;
		}

		/**
		 * @return Le nombre de boucles de la fonction principale de l'algorithme de (dé)chiffrement.
		 */
		public byte getNbRounds() {
			return nbRounds;
		}

		/**
		 * @return Le nombre de sous-clés à générer (en comptant la clé principale).
		 */
		public byte getNbKeys() {
			return nbKeys;
		}
	}

}
