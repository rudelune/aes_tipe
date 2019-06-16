package fr.rudelune.aes;

/**
 * @author rudelune
 */
public class Key {

	private final AESConfig	config;
	private final byte[][]	key;
	private byte[][]		iv;

	private byte[][][]		keyScheduled	= null;

	Key(AESConfig config) {
		this(config, config.generateKey());
		System.out.println("- Utilisation de la clé suivante :");
		Util.displayByteMatrix(key);
	}

	Key(AESConfig config, byte[][] key) {
		this(config, key, config.needIV() ? Util.generateRandomByteMatrix(4) : null);
		if (config.needIV()) {
			System.out.println("- Utilisation du vecteur d'initialisation suivant :");
			Util.displayByteMatrix(iv);
		}
	}

	private Key(AESConfig config, byte[][] key, byte[][] iv) {
		this.config = config;
		this.key = key;
		this.iv = iv;
	}

	/**
	 * Calcule la clé étendue à partir de la principale.
	 *
	 * @return Clé étendue.
	 */
	private byte[][][] calcKeys() {
		boolean minsc = config.isMinsc();
		byte keyLength = (byte) key[0].length;
		byte nbKeys = config.getKeyLength().getNbKeys();
		byte nbRounds = config.getKeyLength().getNbRounds();

		byte[][] keysAssembled = new byte[nbKeys * 4][4];
		for (byte i = 0; i < 4; i++) {
			for (int j = 0; j < keyLength; j++) {
				keysAssembled[j][i] = key[i][j];
			}
		}

		byte lastRCON = (byte) 1;

		for (byte i = 0; i < nbRounds; i++) {
			int line = keyLength * (i + 1);
			keysAssembled[line] = Util.xor(
					Util.replaceSBOX(Util.shift(keysAssembled[line - 1], (byte) -1), false, minsc),
					keysAssembled[line - keyLength]);
			keysAssembled[line][0] ^= lastRCON;
			lastRCON = GaloisMult.xtime(lastRCON);
			for (byte j = 1; j < 4; j++) {
				keysAssembled[line + j] = Util.xor(keysAssembled[line - keyLength + j], keysAssembled[line + j - 1]);
			}

			if (keyLength == 8 && i != nbRounds - 1) {
				keysAssembled[line + 4] = Util.xor(Util.replaceSBOX(keysAssembled[line + 3].clone(), false, minsc),
						keysAssembled[line - keyLength + 4]);
				for (byte j = 5; j < 8; j++) {
					keysAssembled[line + j] = Util.xor(keysAssembled[line - keyLength + j],
							keysAssembled[line + j - 1]);
				}
			} else if (keyLength == 6 && i != nbRounds - 1) {
				for (byte j = 4; j < 6; j++) {
					keysAssembled[line + j] = Util.xor(keysAssembled[line - keyLength + j],
							keysAssembled[line + j - 1]);
				}
			}
		}

		byte[][][] keys = new byte[nbKeys][4][4];
		for (byte i = 0; i < nbKeys; i++) {
			for (byte j = 0; j < 4; j++) {
				for (byte k = 0; k < 4; k++) {
					keys[i][k][j] = keysAssembled[i * 4 + j][k];
				}
			}
		}

		return keys;
	}

	/**
	 * Permet de récupérer la configuration de l'algorithme associé à cette clé.
	 *
	 * @return Configuration de l'algorithme.
	 */
	AESConfig getConfig() {
		return config;
	}

	byte[][][] getKeyScheduled() {
		assert key != null : "Impossible de générer les sous-clés à partir d'une clé publique.";
		if (keyScheduled == null) {
			keyScheduled = calcKeys();
		}
		return keyScheduled;
	}

	/**
	 * Permet de cloner le vecteur d'initalisation pour éviter sa modification involontaire.
	 *
	 * @return Vecteur d'initilisation cloné.
	 */
	public byte[][] cloneIV() {
		return iv.clone();
	}

	/**
	 * Permet de modifier le vecteur d'initialisation.
	 *
	 * @param iv
	 *            Nouveau vecteur d'initialisation.
	 */
	public void changeIV(byte[] iv) {
		this.iv = Util.convertByteArrayToByteMatrix(iv);
	}

	/**
	 * Permet de récupérer la clé principale.
	 *
	 * @return Clé principale.
	 */
	byte[][] getMainKey() {
		return key;
	}

	/**
	 * Permet de récupérer la clé publique dans laquelle seule les informations publiques sont inscrites.
	 *
	 * @return Clé publique.
	 */
	Key getPublicKey() {
		return new Key(config, null, iv);
	}

}
