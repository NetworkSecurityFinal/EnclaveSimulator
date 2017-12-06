package isv.server;

import java.net.ServerSocket;
import java.net.Socket;
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
		} catch (Exception e)
		{
			System.out.println(e);
		}
	}

	public void ProvisionResponse()
	{

	}
}
