package isv.enclave;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

/**
 * This class is a wrapper for the enclave, to make the calls easier for the
 * client
 * 
 * @author Madeline MacDonald & Benjamin Kargul & Jen Simons & Makenzie Elliott
 */
public class EnclaveManagement
{

	private Enclave enclave;
	private DHParameterSpec dhParamSpec;

	public EnclaveManagement()
	{
		enclave = new Enclave("testfile.txt", -1);
		dhParamSpec = new DHParameterSpec(new BigInteger("47"), new BigInteger("71"));
	}

	/**
	 * Create message 0 to respond to the Service Provider's challenge
	 * 
	 * @return String comprising message 0 of the remote attestation protocol
	 * @throws IllegalStateException
	 *             Unrecognized RA provider
	 * @throws Exception
	 */
	public String getMessage0(PublicKey spPubKey) throws Exception
	{
		// Create the PSE session, which is an architectural enclave provided by
		// the SDK
		enclave.sgx_create_pse_session();
		
		// Initialize the enclave for remote attestation
		//Requires the service provider's public key, and the p & q values for DH
		enclave.sgx_ra_init(spPubKey, dhParamSpec);
		
		// Close the PSE session safely
		enclave.sgx_close_pse_session();

		// get the extended group id, which specifies the remote attestation
		// provider
		int extGID = enclave.sgx_get_extended_epid_group_id();

		// 0 indicates that Intel is our remote attestation service provider
		//If there is another value, our application doesn't know how to attest it
		if (extGID != 0)
		{
			throw new IllegalStateException("Unrecognized remote attestation provider");
		}
		
		return Integer.toString(extGID);
	}
	
	/**
	 * Verifies that the server will continue remote attestation
	 * @param response The response from the server
	 * @return If attestation can continue
	 */
	public Boolean verifyMessage0Response(String response)
	{
		return response.equals("Continue");
	}
	
	/**
	 * Retrieves message 1, which is the DH value from the enclave.
	 * In a real ISV situation this would include more enclave calls with pointers to
	 * relevant stub functions, but for the purposes of this simulation they are omitted
	 * @return Message 1
	 */
	public byte[] getMessage1()
	{
		return enclave.sgx_ra_get_msg1();
	}
	
	/**
	 * Verifies the service provider's signature
	 * Calculates the DH shared key
	 * A real ISV would check the SigRL, but this step is omitted
	 * @param m2 Message 2
	 * @return Message 3, the response to Message 2
	 */
	public byte[] processMessage2(String m2)
	{
		return enclave.sgx_ra_proc_msg2(m2);
	}
	
	/**
	 * Verifies the final attestation status from the server
	 * @param m4 message 4
	 * @return If the enclave is verified
	 */
	public Boolean verifyMessage4(String m4)
	{
		return m4.equals("raTrustAll") || m4.equals("raTrustEnclaveOnly");
	}

	/**
	 * Retrieves the enclave object
	 * 
	 * @return enclave
	 */
	public Enclave getEnclave()
	{
		return enclave;
	}

	/**
	 * An API that destroys the enclave if the enclave_id is 0. It is a better
	 * practice to destroy an enclave when not in use
	 */
	void DestroyEnclave()
	{
	}

	/**
	 * An API that creates an enclave If the enclave_id is not 0, it means an
	 * enclave already exists and so the API does nothing, just returns;
	 * otherwise checks the device status using sgx_device_status. If sgx is
	 * enabled, creates the enclave using sgx_create_enclave() API.
	 * 
	 */
	void CreateEnclave()
	{
	}

	/**
	 * An API that encrypts and decrypts the given data buffer
	 * 
	 * @param -input: buffer of string type. This buffer will be encrypted with
	 *        the secret key and decrypted using the secret key by this API
	 *        output: Prints the decrypted message to the buffer and returns the
	 *        status as SUCCESS if the encryption and decryption operations go
	 *        well if not the function aborts with the related error message
	 */
	String EncryptAndDecryptEnclaveCalls(String buffer)
	{
		return "";
	}

	// A wrapper function that destroys and creates enclave
	void DestroyAndCreateEnclave()
	{
	}
}