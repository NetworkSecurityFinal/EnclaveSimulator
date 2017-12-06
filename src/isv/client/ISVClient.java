package isv.client;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;


public class ISVClient
{
	 /**
	  * This section of code is used for the enclave attack simulation.
	  * This code runs the code that allows the General to make a call to the enclave.
	  * 
	  * @author Madeline MacDonald & Benjamin Kargul & Jen Simons & Makenzie Elliott
	  */
	public static void main(String[] args) throws IOException
	{

		General g1 = new General("general1", 12345L);
		General g2 = new General("general2", 56789L);

		General activeGeneral = g1;

		Socket s = new Socket("localhost", 9090);

		DataOutputStream enclaveOut = new DataOutputStream(s.getOutputStream());
		BufferedReader input = new BufferedReader(new InputStreamReader(s.getInputStream()));

		try
		{
			String signature = activeGeneral.sign();
			enclaveOut.writeBytes(activeGeneral.getName() + ":" + signature + "\n");
		} catch (Exception e)
		{
			e.printStackTrace();
			return;
		}

		String answer = input.readLine();
		System.out.println(answer);
		System.exit(0);
	}

}
