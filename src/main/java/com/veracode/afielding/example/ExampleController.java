package com.veracode.afielding.example;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

// Ideally use java.util.Base64 (https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html)
// which is available from Java 8
import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.net.URLEncoder;
import java.util.Arrays;

// Reference:
// https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#only-deserialize-signed-data
// "If the application knows before deserialization which messages will need to be processed,
// they could sign them as part of the serialization process.
// The application could then to choose not to deserialize any message which didn't have an authenticated signature."
//
// For the crypto implementation see this article:
// https://www.veracode.com/blog/secure-development/message-authentication-code-mac-using-java

@RestController
public class ExampleController {
	private SecretKeySpec hmacKeySpec;

	public ExampleController() throws NoSuchAlgorithmException {
		// Todo: Generate a secure HMAC and store it somewhere securely outside the application code-base.
		// The secret should be passed to the application via for example an environment variable.
		// Or, alternatively generate a new HMAC if desired on class construction, however any
		// previously serialized data will now no longer be deserializable
		KeyGenerator keygen = KeyGenerator.getInstance("HmacSHA512"); // Use a secure underlying hash for HMAC algorithm.
		keygen.init(256); // Explicitly initializing keyGenerator. Specify key size, and trust the provider supplied randomness.
		this.hmacKeySpec = new SecretKeySpec(keygen.generateKey().getEncoded(), "HmacSHA512"); // SecretKey holds Symmetric Key(K)
	}

	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String index() {
		return "<a href='/deserialize-insecure?data=" + this.insecureSerialize("Test 1") + "'>Insecure Deserialize 1</a>"
		+ "<br>"
		+ "<a href='/deserialize-insecure?data=" + this.insecureSerialize("Test 2") + "'>Insecure Deserialize 2</a>"
		+ "<br>"
		+ "<a href='/deserialize-secure?data=" + this.secureSerialize("Test 1") + "'>Secure Deserialize 1</a>"
		+ "<br>"
		+ "<a href='/deserialize-secure?data=" + this.secureSerialize("Test 2") + "'>Secure Deserialize 2</a>";
	}

	@RequestMapping(value = "/deserialize-insecure", method = RequestMethod.GET)
	public String handleInsecureDeserializationRequest(String data) {
		return (String)this.insecureDeserialize(data);
	}

	@RequestMapping(value = "/deserialize-secure", method = RequestMethod.GET)
	public String handleSecureDeserializationRequest(String data) {
		return (String)this.secureDeserialize(data);
	}

	// DO NOT USE THIS METHOD. IT IS INSECURE!!
	// DO NOT USE THIS METHOD. IT IS INSECURE!!
	// DO NOT USE THIS METHOD. IT IS INSECURE!!
	// DO NOT USE THIS METHOD. IT IS INSECURE!!
	private String insecureSerialize(Object obj) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		try {
			ObjectOutputStream out = new ObjectOutputStream(bos);
			out.writeObject(obj);
			out.flush();
			byte[] serializedData = bos.toByteArray();
			return URLEncoder.encode(Base64.encodeBase64String(serializedData));
		} catch (Exception e) {
			// Ignore
			e.printStackTrace();
		} finally {
			try {
				bos.close();
			} catch (IOException e) {
				// Ignore
				e.printStackTrace();
			}
		}

		return null;
	}

	// DO NOT USE THIS METHOD. IT IS INSECURE!!
	// DO NOT USE THIS METHOD. IT IS INSECURE!!
	// DO NOT USE THIS METHOD. IT IS INSECURE!!
	// DO NOT USE THIS METHOD. IT IS INSECURE!!
	private Object insecureDeserialize(String serialized) {
		byte[] serializedData = Base64.decodeBase64(serialized);
		ObjectInput in = null;

		try {
			in = new ObjectInputStream(new ByteArrayInputStream(serializedData));
			return in.readObject();
		} catch (Exception e) {
			// Ignore
			e.printStackTrace();
		} finally {
			try {
				if (in != null) {
					in.close();
				}
			} catch (IOException e) {
				// Ignore
				e.printStackTrace();
			}
		}

		return null;
	}

	private String secureSerialize(Object obj) {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		try {
			ObjectOutputStream out = new ObjectOutputStream(bos);
			out.writeObject(obj);
			out.flush();
			byte[] serializedData = bos.toByteArray();

			// THIS IS THE SECURITY CONTROL TO ADD
			//
			// A "$" is not a valid character in the Base64 alphabet (https://en.wikipedia.org/wiki/Base64)
			// We can use this to delimit the data:
			// HMAC$Data
			return URLEncoder.encode(Base64.encodeBase64String(this.computeMac(serializedData)) +"$" + Base64.encodeBase64String(serializedData));
			//
			// ^^ THIS IS THE SECURITY CONTROL TO ADD ^^
		} catch (Exception e) {
			// Ignore
			e.printStackTrace();
		} finally {
			try {
				bos.close();
			} catch (IOException e) {
				// Ignore
				e.printStackTrace();
			}
		}

		return null;
	}

	private Object secureDeserialize(String serializedWithHMAC) {
		// Assert serializedWithHMAC contains exactly 1 "$" character
		// https://stackoverflow.com/a/8910767
		if (serializedWithHMAC.length() - serializedWithHMAC.replace("$", "").length() != 1) {
			return null;
		}

		ObjectInput in = null;

		try {
			// THIS IS THE SECURITY CONTROL TO ADD
			//
			byte[] untrustedHmac = Base64.decodeBase64(serializedWithHMAC.split("\\$")[0]);
			byte[] serializedData = Base64.decodeBase64(serializedWithHMAC.split("\\$")[1]);
			
			// If the HMACs match, we know the data has not been tampered with.
			// Otherwise we bail out and do not attempt to deserialize.
			if (!Arrays.equals(this.computeMac(serializedData), untrustedHmac)) {
				return null;
			}
			//
			// ^^ THIS IS THE SECURITY CONTROL TO ADD ^^

			in = new ObjectInputStream(new ByteArrayInputStream(serializedData));
			return in.readObject();
		} catch (Exception e) {
			// Ignore
			e.printStackTrace();
		} finally {
			try {
				if (in != null) {
					in.close();
				}
			} catch (IOException e) {
				// Ignore
				e.printStackTrace();
			}
		}

		return null;
	}

	private byte[] computeMac(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance("HmacSHA512"); // get access to Mac object which implements HmacSHA512 algorithm.
		mac.init(this.hmacKeySpec); // Initialize Mac object with symmetric key(K), same as with sender
		mac.update(data); // add message data (M) to Mac object to compute Mac.
		return mac.doFinal(); // Compute MAC
	}
}