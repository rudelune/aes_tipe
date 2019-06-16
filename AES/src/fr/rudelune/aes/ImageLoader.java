package fr.rudelune.aes;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.crypto.BadPaddingException;
import javax.imageio.ImageIO;

/**
 * @author rudelune
 */
class ImageLoader {

	private final String	path;
	private final String	fileName;
	private final String	extension;
	private final int		height, width;
	private byte[]			data;

	ImageLoader(String file) throws IOException {
		Path path = Paths.get(file);
		this.path = path.getParent().toString();
		fileName = path.getFileName().toString();
		extension = fileName.substring(fileName.lastIndexOf('.') + 1);
		BufferedImage image = ImageIO.read(new File(file));
		height = image.getHeight();
		width = image.getWidth();
		data = new byte[height * width * 3];
		int color;
		for (int y = 0, total = 0; y < height; y++) {
			for (int x = 0; x < width; x++, total++) {
				color = image.getRGB(x, y);
				data[total * 3] = (byte) (color >> 16);
				data[total * 3 + 1] = (byte) ( (color >> 8) & 0xFF);
				data[total * 3 + 2] = (byte) (color & 0xFF);
			}
		}
	}

	/**
	 * Renvoie un int représentant une couleur.
	 *
	 * @param r
	 *            Rouge
	 * @param g
	 *            Vert
	 * @param b
	 *            Bleu
	 * @return L'entier représentant la couleur caractérisée par son pourcentage de rouge, de vert et de bleu.
	 */
	private static int getRGB(byte r, byte g, byte b) {
		return ( (r & 0xFF) << 16) ^ ( (g & 0xFF) << 8) ^ (b & 0xFF);
	}

	/**
	 * Chiffre l'image (ne la sauvegarde pas).
	 *
	 * @param key
	 *            Clé de chiffrement utilisée.
	 */
	void crypt(Key key) {
		data = Crypt.crypt(data, key);
	}

	/**
	 * Déchiffre l'image (ne la sauvegarde pas).
	 *
	 * @param key
	 *            Clé de déchiffrement utilisée.
	 * @throws BadPaddingException
	 *             Le padding ajouté au chiffrement n'est pas bon.
	 */
	void decrypt(Key key) throws BadPaddingException {
		data = Decrypt.decrypt(data, key);
	}

	/**
	 * Permet de sauvegarder l'image.
	 *
	 * @param prefix
	 *            Permet de rajouter un préfixe devant le nom de l'image pour ne pas remplacer l'ancienne image.
	 * @throws IOException
	 *             Erreur lors de l'écriture du fichier.
	 */
	void save(String prefix) throws IOException {
		BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
		for (int y = 0, total = 0; y < height; y++) {
			for (int x = 0; x < width; x++, total++) {
				image.setRGB(x, y, getRGB(data[total * 3], data[total * 3 + 1], data[total * 3 + 2]));
			}
		}
		ImageIO.write(image, extension, new File(path + File.separatorChar + prefix + fileName));
	}

	/**
	 * Applique l'opération OU-Exclusive à chacun des octets constituant les deux images.
	 *
	 * @param other
	 *            L'autre image (celle dernière reste inchangée).
	 */
	void xor(ImageLoader other) {
		int maxLength = Math.max(data.length, other.data.length);
		for (int i = 0; i < maxLength; i++) {
			data[i] ^= other.data[i];
		}
	}

}
