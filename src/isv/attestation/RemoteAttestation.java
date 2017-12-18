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
			
			//This code is duplicated in the Server
			//Eventually we will have the server sent the public key over to the user as part of the handshake
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, random);
			KeyPair pair = keyGen.generateKeyPair();
			PublicKey spPub = pair.getPublic();
			
			String m0 = em.getMessage0(spPub);
			out.print(m0 + "\r\n");
			String m0Response = in.readLine();

			if(!em.verifyMessage0Response(m0Response))
			{
				System.out.println("Attestation failed: unknown group ID");
			}

			socket.getOutputStream().write(em.getMessage1());

			String m2 = in.readLine();
			socket.getOutputStream().write(em.processMessage2(m2));
			
			String m4 = in.readLine();

			if (!em.verifyMessage4(m4)) {
				System.out.println("Attestation Failed with Server response " + m4);
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
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