package isv.attestation;

import isv.enclave.EnclaveManagement;

import java.net.Socket;
import java.io.*;

/**
 * Connects to ISV Server which will handle remote attestation of enclave
 * 
 * @author Madeline MacDonald & Benjamin Kargul & Jen Simons & Makenzie Elliott
 */
public class RemoteAttestation{
  
  Socket socket;
  int DEFAULT_PORT = 1111; //default is usually 80
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
  public RemoteAttestation(EnclaveManagement em, String ip, int port){
    this.em = em;
    this.ip = ip;
    this.port = port;
    connect();
  } 
  public void connect(){
    try {
      socket = new Socket(ip, DEFAULT_PORT);
      in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
      out = new PrintWriter(socket.getOutputStream(), true);
      System.out.println("Connected");
      provisionRequest();
    }catch(Exception e){
      System.err.println("Failure to connect (RemoteAttestation.connect) : " + e);  
      close();
    }
  }
  /**
   * Contacts ISV server for initial handshake 
   * 
   */
  public void provisionRequest(){
    
  }
  /**
   * Disconnects socket from connection and closes BufferedReader and PrintWriter
   * 
   */
  public void close(){
    try{
      in.close();
    }catch(Exception e){
      System.err.println("Failure to close BufferedReader (RemoteAttestation.close) : " + e);
    }
    out.close();
    try{
      socket.close();
    }catch(Exception e){
      System.err.println("Failure to close socket (RemoteAttestation.close) : " + e);
    }
  }
}