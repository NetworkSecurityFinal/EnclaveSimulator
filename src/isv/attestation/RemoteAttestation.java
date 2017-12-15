package isv.attestation;

import isv.enclave.EnclaveManagement;

import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.io.*;

/**
 * Connects to ISV Server which will handle remote attestation of enclave
 * 
 * @author Madeline MacDonald & Benjamin Kargul & Jen Simons & Makenzie Elliott
 */
public class RemoteAttestation {

	Socket socket;
	int DEFAULT_PORT = 1111; // default is usually 80
	String ip;
	int port;
	BufferedReader in;
	PrintWriter out;
	EnclaveManagement em;

	public RemoteAttestation(EnclaveManagement em) {
		this.em = em;
		ip = "localhost";
		port = DEFAULT_PORT;
		connect();
	}

	public RemoteAttestation(EnclaveManagement em, String ip, int port) {
		this.em = em;
		this.ip = ip;
		this.port = port;
		connect();
	}

	public void connect() {
		try {
			socket = new Socket(ip, DEFAULT_PORT);
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new PrintWriter(socket.getOutputStream(), true);
			System.out.println("Connected");
			provisionRequest();
			attestEnclave();
		} catch (Exception e) {
			System.err.println("Failure to connect (RemoteAttestation.connect) : " + e);
			close();
		}
	}

	/**
	 * Contacts ISV server for initial handshake
	 * 
	 */
	public void provisionRequest() {
		// In a real ISV situation this would possibly be an SSL handshake, or something
		// similar
		// For our purposes this can be left empty,
		// because this step varies depending on ISV implementation
	}

	public void attestEnclave() {
		// How to get public key from service provider, sign and verify with it?
		PublicKey spPubKey;

		try {
			
			//This should happen on the server, and then get sent over as part of the handshake
			//For now we generate it ourselves
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, random);
			KeyPair pair = keyGen.generateKeyPair();
			PublicKey spPub = pair.getPublic();
			
			em.getMessage0(spPub);
			// send message 0
			// get response from message 0
			em.verifyMessage0Response("Continue");

			String m1 = em.getMessage1();
			// send message 1
			// wait for response from message

			String m3 = em.processMessage2("");
			// send message 3
			// wait for response

			if (!em.verifyMessage4("")) {
				// Throw some sort of descriptive error here
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Disconnects socket from connection and closes BufferedReader and PrintWriter
	 * 
	 */
	public void close() {
		try {
			in.close();
		} catch (Exception e) {
			System.err.println("Failure to close BufferedReader (RemoteAttestation.close) : " + e);
		}
		out.close();
		try {
			socket.close();
		} catch (Exception e) {
			System.err.println("Failure to close socket (RemoteAttestation.close) : " + e);
		}
	}
}