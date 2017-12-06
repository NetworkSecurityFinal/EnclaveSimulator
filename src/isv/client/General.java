package isv.client;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

/**
 * A model of the General used for the simulated attack.
 * 
 * @author Madeline MacDonald & Benjamin Kargul & Jen Simons & Makenzie Elliott
 */
public class General
{
	private String name;
	private long seed;
	private KeyPair pair;
	private boolean hasAuthorized;
	private PrivateKey privKey;
	private PublicKey pubKey;

	public General(String name, long seed)
	{
		this.setName(name);
		this.setSeed(seed);
		this.setPair(this.generateKeyPair(seed));
		this.setPriv(this.pair.getPrivate());
		this.setPub(this.pair.getPublic());
		this.setHasAuthorized(false);
	}

	public static void main(String[] args) throws IOException
	{

		General g1 = new General("general1", 12345L);
		General g2 = new General("general2", 56789L);

		General activeGeneral = g1;

		Socket s = new Socket("localhost", 9090);

		DataOutputStream enclaveOut = new DataOutputStream(s.getOutputStream());
		BufferedReader enclaveIn = new BufferedReader(new InputStreamReader(s.getInputStream()));

		try
		{
			String signature = activeGeneral.sign();
			enclaveOut.writeBytes(activeGeneral.getName() + ":" + signature + "\n");
		} catch (Exception e)
		{
			e.printStackTrace();
			return;
		}
		// Sending Alices public key to Bob

		BufferedReader input = new BufferedReader(new InputStreamReader(s.getInputStream()));
		String answer = input.readLine();
		System.out.println(answer);
		System.exit(0);
	}

	@SuppressWarnings("finally")
	public KeyPair generateKeyPair(long s)
	{
		KeyPair pair = null;
		try
		{
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			random.setSeed(s);
			keyGen.initialize(2048, random);

			pair = keyGen.generateKeyPair();
		} catch (Exception e)
		{
			e.printStackTrace();
		} finally
		{
			return pair;
		}
	}

	public String sign() throws Exception
	{
		String plaintext = this.name;

		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(privKey);
		privateSignature.update(plaintext.getBytes());

		byte[] signature = privateSignature.sign();

		return Base64.getEncoder().encodeToString(signature);
	}

	public boolean hasAuthorized()
	{
		return hasAuthorized;
	}

	public void setHasAuthorized(boolean hasAuthorized)
	{
		this.hasAuthorized = hasAuthorized;
	}

	public long getSeed()
	{
		return seed;
	}

	public void setSeed(long seed)
	{
		this.seed = seed;
	}

	public String getName()
	{
		return name;
	}

	public void setName(String name)
	{
		this.name = name;
	}

	private KeyPair getPair()
	{
		return pair;
	}

	private void setPair(KeyPair pair)
	{
		this.pair = pair;
	}

	private PrivateKey getPriv()
	{
		return privKey;
	}

	private void setPriv(PrivateKey priv)
	{
		this.privKey = priv;
	}

	public PublicKey getPub()
	{
		return pubKey;
	}

	private void setPub(PublicKey pub)
	{
		this.pubKey = pub;
	}
}