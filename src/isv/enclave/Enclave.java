package isv.enclave;

import isv.client.General;

import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashSet;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

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
	protected String sgx_ra_get_msg1() {
		return dhKeyPair.getPublic().toString();
	}

	/**
	 * Verifies the service provider's signature Check the SigRl (Omited from the
	 * simulation) Generates Message 3, the response to Message 2. This message
	 * contains a qoute from the enclave signed with the platform's EPID key. Only
	 * Intel Attestation Services can verify this signature Because this is a
	 * simulation, and we don't have EPID keys, this signing step is omitted
	 */
	protected String sgx_ra_proc_msg2(String m2) {

		// verify the service provider signature
		// Check the SigRl
		return GetQuote();
	}

	// some code goes in here to get the quote for the enclave
	//
	private String GetQuote() {
		return "";
	}
}
