package isv.enclave;

import isv.client.General;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashSet;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

/**
 * Software simulation of an SGX enclave that exposes a subset of the SGX
 * instruction set used for remote attestation
 * 
 * The Enclave also includes a simulation of an algorithm that is vulnerable to
 * enclave state malleability.
 * 
 * @author Madeline MacDonald & Benjamin Kargul & Jen Simons & Makenzie Elliott
 * 
 */
public class Enclave {

	// fields used for the enclave attack simulation
	private boolean createInterrupt;
	private int authCount;
	private HashSet<General> generalInfo;

	/*
	 * These are hardware keys in a real enclave these would have been generated
	 * when the enclave was created These are kept hidden from the manufacturer
	 * (Intel) and used to generate other provisioning keys
	 */
	private static byte[] sealing_key = new byte[16];
	private static byte[] provisioning_key = new byte[16];

	private int eid;
	private String FileName;
	private PublicKey spPublicKey;
	private KeyPair dhKeyPair;
	private KeyAgreement dhKeyAgree;
	// Hold the p and g values for the DHKE
	private DHParameterSpec paramSpec;
	// final shared DH key
	byte[] sharedKeyBytes;

	static {

		// generate keys in a static block
		// to simulate their creation when the hardware was made
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(provisioning_key);
		sr.nextBytes(sealing_key);
	}

	/**
	 * Creates a new instance of an enclave simulator that exposes a subset of the
	 * SGX instruction set used for remote attestation. This is equivalent to
	 * sgx_create_enclave()
	 * 
	 * @param enclaveFileName
	 * @param enclaveID
	 */
	protected Enclave(String enclaveFileName, int enclaveID) {
		// Make the choice to not load enclave file
		// Don't use a creation token

		eid = enclaveID;
	}

	protected Enclave() {
		setAuthCount(0);
		setGeneralInfo(new HashSet<>());
		setCreateInterrupt(false);
	};

	protected static void main(String args[]) {
		enclaveAttackSimulation();
	}

	/**
	 * Reads in the request from the environment code and calls
	 */
	protected static void enclaveAttackSimulation() {
		System.out.println("Enclave listening...");

		Enclave enclave = new Enclave();
		General g1 = new General("general1", 12345L);
		General g2 = new General("general2", 56789L);

		enclave.addGeneralToAuth(g1);
		enclave.addGeneralToAuth(g2);

		ServerSocket listener = null;

		try {
			listener = new ServerSocket(9090);
			while (true) {
				Socket socket = listener.accept();

				new Thread(new ThreadWorker(socket, enclave)).start();

			}

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	protected void addGeneralToAuth(General g) {
		this.generalInfo.add(g);

	}

	protected int getAuthCount() {
		return authCount;
	}

	protected void setAuthCount(int authCount) {
		this.authCount = authCount;
	}

	protected boolean createInterrupt() {
		return createInterrupt;
	}

	protected void setCreateInterrupt(boolean createInterrupt) {
		this.createInterrupt = createInterrupt;
	}

	protected HashSet<General> getGeneralInfo() {
		return generalInfo;
	}

	protected void setGeneralInfo(HashSet<General> generalInfo) {
		this.generalInfo = generalInfo;
	}

	/*
	 * These functions are for initializing PSE, which is where TPM logic would be
	 * called These need to be called before and after sgx_ra_init() These methods
	 * would be used in some of the proposed attacks our group considered but
	 * ultimately we decided against using them. These are left in for illustrative
	 * purposes
	 */
	protected void sgx_create_pse_session() {
	}

	protected void sgx_close_pse_session() {
	}

	/**
	 * Initializes the enclave for remote attestation. Stores the service provider's
	 * public key, and initializes a Diffie Hellman key exchange
	 * 
	 * @param spPubKey
	 *            The service provider's public key
	 */
	protected void sgx_ra_init(PublicKey spPubKey, DHParameterSpec paramSpec) {
		try {
			this.paramSpec = paramSpec;
			spPublicKey = spPubKey;
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DiffieHellman");
			kpg.initialize(paramSpec);
			dhKeyPair = kpg.generateKeyPair();
			dhKeyAgree = KeyAgreement.getInstance("DiffieHellman");
			dhKeyAgree.init(dhKeyPair.getPrivate());

		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println(e.getMessage());
		} catch (InvalidKeyException e) {
			System.out.println(e.getMessage());
		}
	}

	/**
	 * retrieves the extended group ID, which indicates the attestation service
	 * provider 0 indicates Intel's attestation service, != 0 indicates a third
	 * party attestation service
	 * 
	 * This simulated enclave follows Intel's attestation protocol
	 * 
	 * @return extended group id
	 */
	protected int sgx_get_extended_epid_group_id() {
		return 0;
	}

	/**
	 * @return a DH value from the enclave
	 * 
	 */
	protected byte[] sgx_ra_get_msg1() {
		return dhKeyPair.getPublic().getEncoded();
	}

	/**
	 * Verifies the service provider's signature Check the SigRl (Omitted from the
	 * simulation) Generates Message 3, the response to Message 2. This message
	 * contains a quote from the enclave signed with the platform's EPID key. Only
	 * Intel Attestation Services can verify this signature Because this is a
	 * simulation, and we don't have EPID keys, this signing step is omitted
	 */
	protected byte[] sgx_ra_proc_msg2(String m2) {

		// verify the service provider signature
		// Not implemented currently

		String[] parts = m2.split(" ");

		// calculate the DH shared key
		sharedKeyBytes = computeSharedKey(parts[0].getBytes());

		// Check the SigRl (Omitted)

		return GetQuote();
	}

	// This code is from
	// https://stackoverflow.com/questions/21081713/diffie-hellman-key-exchange-in-java
	// It was the best explanation of how to use the java libraries for DH
	// and so in the interest of saving time to focus on the enclave implementation
	// details we chose to use this
	public byte[] computeSharedKey(byte[] pubKeyBytes) {
		if (dhKeyAgree == null) {
			System.out.println("Key Agreement is Null");
			return null;
		}

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
			BigInteger pubKeyBI = new BigInteger(1, pubKeyBytes);
			PublicKey pubKey = keyFactory
					.generatePublic(new DHPublicKeySpec(pubKeyBI, paramSpec.getP(), paramSpec.getG()));
			dhKeyAgree.doPhase(pubKey, true);
			byte[] sharedKeyBytes = dhKeyAgree.generateSecret();
			return sharedKeyBytes;
		} catch (Exception e) {
			System.out.println(e.getMessage());
			return null;
		}
	}

	/**
	 * Intel's documentation is fairly sparse on exactly what is contained in a
	 * Quote So we chose to implement this as just having some metadata from the
	 * enclave collected and packaged up This quote would be signed by an EPID,
	 * which is a hardware specific key that only the Intel attestation service can
	 * decrypt, but due to limitations in hardware we're using the shared DH key to encrypt this instead
	 * 
	 * @return The enclave quote
	 */
	private byte[] GetQuote() {

		try {
			ByteBuffer b = ByteBuffer.allocate(4);
			b.putInt(eid);

			byte[] data = b.array();

			PrivateKey privateKey = KeyFactory.getInstance("RSA")
					.generatePrivate(new PKCS8EncodedKeySpec(sharedKeyBytes));
			Signature sig = Signature.getInstance("SHA1WithRSA");

			sig.initSign(privateKey);
			sig.update(data);

			return sig.sign();
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		return null;

	}
}
