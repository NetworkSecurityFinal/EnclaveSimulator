package isv.server;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.math.BigInteger;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.KeyAgreement;
import java.io.*;

/**
 * 
 * 
 * @author Madeline MacDonald & Benjamin Kargul & Jen Simons & Makenzie Elliott
 */


public class ISVServer
{

 static ServerSocket ss; // TCP socket for server
 static int DEFAULT_PORT = 1111; // default is usually 80
 static PrintWriter out;
 static BufferedReader in;
 static KeyPair dhKeyPair;
 static DHParameterSpec paramSpec;
 static KeyAgreement dhKeyAgree;
 // final shared DH key
 static byte[] sharedKeyBytes;
 public static void main(String[] args)
 {
  try
  {
   ss = new ServerSocket(DEFAULT_PORT);
   System.out.println("Server listening on port " + DEFAULT_PORT);
   Socket socket = ss.accept();
   in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
   out = new PrintWriter(socket.getOutputStream(), true);
   System.out.println("Client connected");
   
   //get protocol code
   String m0 = in.readLine();
   System.out.println(m0);
   if(true)
     out.print("Continue");
   //get diffie hellman value from client
   String m1 = in.readLine();
   sharedKeyBytes = computeSharedKey(m1.getBytes());
   //send over servers DH value
   out.print(dhKeyPair.getPublic().getEncoded() + " N/A");
   //send over the attestation status
   out.print(attestationStatus());

  } catch (Exception e)
  {
   System.out.println(e);
  }
 }

 public static void ProvisionResponse()
 {
   //Left blank for now as this is up to the ISV and client to negotiate handshakes

 }
 
 public static String attestationStatus(){
 
   //if we trust all
   
   return "raTrustAll";
   //if we trust the enclave
   //return "raTrustEnclaveOnly";
   
   //else send anything
   //return "no trust";
 }
 
 public static void ProvisionPrivateKeys() throws NoSuchAlgorithmException, NoSuchProviderException
 {
  //this public key needs to be sent to the client somehow, ideally during the handshake
  KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
  SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
  keyGen.initialize(1024, random);
  KeyPair pair = keyGen.generateKeyPair();
  PublicKey spPub = pair.getPublic();
 }
 
 public static byte[] computeSharedKey(byte[] pubKeyBytes) {

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
 
}
