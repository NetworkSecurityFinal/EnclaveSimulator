package isv.enclave;

import isv.client.General;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.Signature;
import java.util.Base64;

/**
 * This class is the thread worker for the enclave. It allows the enclave to be
 * multithreaded so that two different Generals can authorize a nuclear attack.
 * 
 * @author Madeline MacDonald & Benjamin Kargul & Jen Simons & Makenzie Elliott
 */
public class ThreadWorker implements Runnable
{

	protected Socket _clientSocket = null;
	protected Enclave _enclave;

	static final String INVALID_GENERAL = "INVALID_GENERAL";
	static final String GENERAL_ALREADY_AUTHORIZED_ACTION = "GENERAL_ALREADY_AUTHORIZED_ACTION";
	static final String PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION";
	static final String INTERRUPT = "INTERRUPT";

	public ThreadWorker(Socket socket, Enclave enclave)
	{
		this._clientSocket = socket;
		this._enclave = enclave;
	}

	/**
	 * This thread working reads in the request from the General and executes a
	 * enclave function. For the attack simulation, the enclave reads in that
	 * the environment code wants to envoke the function authAndLaunch. They do
	 * so by sending to the enclave: [generals-name : generals-signature]
	 */
	public void run()
	{
		try
		{
			DataOutputStream generalOut = new DataOutputStream(_clientSocket.getOutputStream());
			BufferedReader generalIn = new BufferedReader(new InputStreamReader(_clientSocket.getInputStream()));

			String message = generalIn.readLine();
			String[] messageInfo = message.split(":");

			String generalName = messageInfo[0];
			String signature = messageInfo[1];

			String result = authAndLaunch(generalName, signature);

			generalOut.writeBytes(result + "\n");
		} catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	/**
	 * This authAndLaunch function lives within the enclave and only the
	 * predefined function call is available to the outside environment. This
	 * function takes in a generals name and the signature, and authorized a
	 * nuclear launch.
	 * 
	 * @param generalName
	 *            name of the general
	 * @param signature
	 *            the name of the general and other data signed by the general
	 * @return the status of the enclave to the environment
	 * @throws Exception
	 */
	public String authAndLaunch(String generalName, String signature) throws Exception
	{
		// get the general from the Enclave saved data
		General general = getGeneral(generalName);

		// validate the generals name and signature
		boolean validateResult = validateGeneral(generalName, signature);

		// if the signature doesn't match, invalid general
		if (!validateResult)
		{
			return INVALID_GENERAL;
		}

		// if the general hasn't authorized yet, let him/her do so. Otherwise
		// report the general already authrozied once.
		if (!general.hasAuthorized())
		{
			_enclave.setAuthCount(_enclave.getAuthCount() + 1);
			if (_enclave.createInterrupt())
			{
				_enclave.setCreateInterrupt(false);
				return INTERRUPT;
			}
			general.setHasAuthorized(true);
		} else
		{
			return GENERAL_ALREADY_AUTHORIZED_ACTION;
		}

		// if two generals have authorized the launch, send the nuke!
		if (_enclave.getAuthCount() >= 2)
		{
			return nukeTheKashbah();
		}

		// otherwise we aren't ready to launch yet.
		return PENDING_AUTHORIZATION;
	}

	private String nukeTheKashbah()
	{
		return "BOOOOOOOOM!";
	}

	public boolean validateGeneral(String generalName, String signature) throws Exception
	{

		General targetGeneral = getGeneral(generalName);
		String plainText = targetGeneral.getName();

		Signature publicSignature = Signature.getInstance("SHA256withRSA");
		publicSignature.initVerify(targetGeneral.getPub());
		publicSignature.update(plainText.getBytes());

		byte[] signatureBytes = Base64.getDecoder().decode(signature);

		return publicSignature.verify(signatureBytes);
	}

	private General getGeneral(String generalName)
	{
		for (General g : _enclave.getGeneralInfo())
		{
			if (g.getName().equals(generalName))
			{
				return g;
			}
		}
		return null;
	}
}
