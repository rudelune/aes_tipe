package fr.rudelune.aes;

import java.nio.charset.Charset;
import java.util.Scanner;

import fr.rudelune.aes.attack.AttackerClient;
import fr.rudelune.aes.attack.VulnerableServer;

/**
 * @author rudelune
 */
class Experiments {

	public static void main(String[] args) throws Exception {
		System.out.println("Ce programme a été développé par rudelune (rudelune) dans le cadre de son TIPE.");

		System.out.println("- Quelle expérience souhaitez-vous tester ?");
		System.out.println("0 - Lancer un test de l'Oracle Padding Attack.");
		System.out.println("1 - Visualiser la principale faiblesse du mode ECB en chiffrant une image.");
		System.out.println("2 - Visualiser la faiblesse générée lorsque l'on utilise le même IV avec le mode OFB.");

		Scanner sc = new Scanner(System.in);
		byte experiment = Byte.parseByte(sc.nextLine());
		if (experiment == 0) {
			Key key = new Key(
					new AESConfig(AESConfig.Mode.CBC, AESConfig.Padding.PKCS7, AESConfig.KeyLength.AES256, false));
			System.out.println("- Quel message voulez-vous chiffrer ?");
			byte[] msg = sc.nextLine().getBytes(Charset.forName("UTF-8"));
			VulnerableServer server = new VulnerableServer();
			byte[] cipherText = server.run(key, msg);
			new AttackerClient(cipherText, key.getPublicKey(), server);
		} else if (experiment == 1) {
			System.out.println("- Quelle image souhaitez-vous chiffrer ?");
			ImageLoader image = new ImageLoader(sc.nextLine());
			image.crypt(new Key(
					new AESConfig(AESConfig.Mode.ECB, AESConfig.Padding.PKCS7, AESConfig.KeyLength.AES256, false)));
			image.save("crypted_");
		} else if (experiment == 2) {
			System.out.println("- Quelle première image souhaitez-vous utiliser ?");
			ImageLoader image = new ImageLoader(sc.nextLine());
			System.out.println("- Quelle seconde image souhaitez-vous utiliser ?");
			ImageLoader image2 = new ImageLoader(sc.nextLine());
			Key key = new Key(
					new AESConfig(AESConfig.Mode.OFB, AESConfig.Padding.PKCS7, AESConfig.KeyLength.AES256, false));
			image.crypt(key);
			image2.crypt(key);
			image.save("crypted_");
			image2.save("crypted_");
			image.xor(image2);
			image.save("xorred_");
		} else {
			System.out.println("Choix invalide !");
		}
		sc.close();
	}

}
