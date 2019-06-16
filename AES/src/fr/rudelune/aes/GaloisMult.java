package fr.rudelune.aes;

/**
 * @author rudelune
 */
class GaloisMult {

	/**
	 * Calcul le produit de deux matrices 4*4 dans GF(256).
	 *
	 * @param array
	 *            Première matrice 4*4.
	 * @param matrix
	 *            Seconde matrice 4*4.
	 * @return Matrice 4*4
	 */
	static byte[][] calc(byte[][] array, byte[][] matrix) {
		byte[][] result = new byte[4][4];
		for (byte i = 0; i < 4; i++) {
			for (byte j = 0; j < 4; j++) {
				result[i][j] = (byte) (calc(matrix[i][0], array[0][j]) ^ calc(matrix[i][1], array[1][j])
						^ calc(matrix[i][2], array[2][j]) ^ calc(matrix[i][3], array[3][j]));
			}
		}
		return result;
	}

	/**
	 * Calcul le produit de a par b dans GF(256).
	 *
	 * @param a
	 *            Premier octet.
	 * @param b
	 *            Second octet.
	 * @return L'octet représentant le produit de a par b.
	 */
	static byte calc(byte a, byte b) {
		if (b == 0) {
			return 0;
		} else {
			return (byte) ( (b % 2 == 0 ? 0 : a) ^ xtime(calc(a, (byte) ( (b & 0xFF) >> 1))));
		}

	}

	/**
	 * Calcul le produit de a par 2 dans GF(256).
	 *
	 * @param a
	 *            Premier octet.
	 * @return L'octet représentant le produit de a par 2.
	 */
	static byte xtime(byte a) {
		return (byte) ( ((byte) (a << 1)) ^ ( ( (a & 0xFF) >> 7 == 0) ? 0 : (byte) 0x1B));
	}

}
