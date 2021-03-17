/**
 * Copyright (C) 2017 - Swisscom (Schweiz) AG
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the 
 * Free Software Foundation, either version 3 of the License, or (at your 
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see http://www.gnu.org/licenses/.
 * 
 * @author <a href="mailto:philipp.haupt@swisscom.com">Philipp Haupt</a>
 */

package ch.swisscom.mid.verifier;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.Principal;
import java.security.Security;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class MobileIdCmsVerifier {

	private CMSSignedData cmsSignedData;
	private X509CertificateHolder x509CertHolder;
	private SignerInformation signerInfo;
	private X509Certificate signerCert;

	public static void main(String[] args) {
		
		if (args == null || args.length < 1) {
			System.out.println("Usage: ch.swisscom.mid.verifier.MobileIdCmsVerifier [OPTIONS]");
			System.out.println();
			System.out.println("Options:");
			System.out.println("  -cms=VALUE or -stdin   - base64 encoded CMS/PKCS7 signature string, either as VALUE or via standard input");
			System.out.println("  -jks=VALUE             - optional path to truststore file (default is 'jks/truststore.jks')");
			System.out.println("  -jkspwd=VALUE          - optional truststore password (default is 'secret')");
			System.out.println();
			System.out.println("Example:");
			System.out.println("  java ch.swisscom.mid.verifier.MobileIdCmsVerifier -cms=MIII...");
			System.out.println("  echo -n MIII... | java ch.swisscom.mid.verifier.MobileIdCmsVerifier -stdin");
			System.exit(1);
		}
		
		try {
			
			MobileIdCmsVerifier midverifier = null;
			
			String jks = "jks/truststore.jks";
			String jkspwd = "secret";
			
			String param;
			for (int i = 0; i < args.length; i++) {	
				param = args[i].toLowerCase();
				if (param.contains("-jks=")) {
					jks = args[i].substring(args[i].indexOf("=") + 1).trim();
				} 
				else if (param.contains("-jkspwd=")) {
					jkspwd = args[i].substring(args[i].indexOf("=") + 1).trim();
				} 
				else if (param.contains("-cms=")) {
					midverifier = new MobileIdCmsVerifier(args[i].substring(args[i].indexOf("=") + 1).trim());
				} 
				else if (param.contains("-stdin")) {
					BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
				    String stdin;
				    if ((stdin = in.readLine()) != null && stdin.length() != 0)
				    	midverifier = new MobileIdCmsVerifier(stdin.trim());
				}
			}
			
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(jks), jkspwd.toCharArray());
			
			// If you are behind a Proxy..
			// System.setProperty("proxyHost", "10.185.32.54");
			// System.setProperty("proxyPort", "8079");
			// or set it via VM arguments: -DproxySet=true -DproxyHost=10.185.32.54 -DproxyPort=8079
			
			// Print Issuer/SubjectDN/SerialNumber of all x509 certificates that can be found in the CMSSignedData
			midverifier.printAllX509Certificates();

			// Print Signer's X509 Certificate Details
			System.out.println("X509 SignerCert SerialNumber: " + midverifier.getX509SerialNumber());
			System.out.println("X509 SignerCert Issuer: " + midverifier.getX509IssuerDN());
			System.out.println("X509 SignerCert Subject DN: " + midverifier.getX509SubjectDN());
			System.out.println("X509 SignerCert Validity Not Before: " + midverifier.getX509NotBefore());
			System.out.println("X509 SignerCert Validity Not After: " + midverifier.getX509NotAfter());
			System.out.println("X509 SignerCert Validity currently valid: " + midverifier.isCertCurrentlyValid());
			System.out.println("X509 SignerCert Key Alogrithm: " + midverifier.getAlgo());

			System.out.println("User's unique Mobile ID SerialNumber: " + midverifier.getMIDSerialNumber());
			
			// Print signed content (should be equal to the DTBS Message of the Signature Request)
			System.out.println("Signed Data: " + midverifier.getSignedData());

			// Verify the signature on the SignerInformation object
			System.out.println("Signature Valid: " + midverifier.isVerified());
			
			// Validate certificate path against trust anchor incl. OCSP revocation check
			System.out.println("X509 SignerCert Valid (Path+OCSP): " + midverifier.isCertValid(keyStore));

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Will attempt to initialize the signer certificate
	 * 
	 * @param cmsSignatureBase64
	 *            Base 64 encoded CMS/PKCS7 String
	 * @throws CMSException
	 * @throws CertificateException
	 */
	public MobileIdCmsVerifier(String cmsSignatureBase64) throws CMSException, CertificateException {
		this.cmsSignedData = new CMSSignedData(Base64.decodeBase64(cmsSignatureBase64));
		// Find the signer certificate
		SignerInformationStore signerInfoStore = cmsSignedData.getSignerInfos();
		signerInfo = (SignerInformation) signerInfoStore.getSigners().iterator().next();
		x509CertHolder = (X509CertificateHolder) cmsSignedData.getCertificates().getMatches(signerInfo.getSID()).iterator().next();
		signerCert = new JcaX509CertificateConverter().getCertificate(x509CertHolder);
	}
	
	/**
	 * Prints Issuer/SubjectDN/SerialNumber of all x509 certificates that can be found in the CMSSignedData
	 * 
	 * @throws CertificateException
	 */
	private void printAllX509Certificates() throws CertificateException {
		
		// Find all available certificates with getMatches(null)
		Iterator<?> certIt = cmsSignedData.getCertificates().getMatches(null).iterator();
		int i = 0;
		
		while (certIt.hasNext()){
			X509CertificateHolder certHolder =  (X509CertificateHolder)certIt.next();
			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
			System.out.println("X509 Certificate #" + ++i);
			System.out.println("X509 Issuer: " + cert.getIssuerDN());
			System.out.println("X509 Subject DN: " + cert.getSubjectDN());
			System.out.println("X509 SerialNumber: " + cert.getSerialNumber());
			System.out.println("SignerCert: " +  (cert.getBasicConstraints() == -1 ? "Yes" : "No"));
			System.out.println("PubKey: " + cert.getPublicKey());
			System.out.println("PubKeyEncoded: " + getHexData(cert.getPublicKey().getEncoded()));
			System.out.println();
		}
	}

	public static String getHexData(final byte[] data) {
		StringBuffer hexBuffer = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			// convert byte to integer value (unsigned)
			int byteValue = data[i] & 0xff;

			// generate HEX value
			String hexValue = Integer.toHexString(byteValue);

			// check if hex representation needs to be prefixed
			if (hexValue.length() < 2) {
				hexBuffer.append("0").append(hexValue);
			} else {
				hexBuffer.append(hexValue);
			}
		}
		return hexBuffer.toString();
	}
	
	
	/**
	 * Validates the specified certificate path incl. OCSP revocation check
	 * 
	 * @param truststore
	 * @return true if all certificate is valid
	 * @throws Exception 
	 */
	private boolean isCertValid(KeyStore truststore) throws Exception {
		List<X509Certificate> certlist = new ArrayList<X509Certificate>();
		certlist.add(signerCert);

		PKIXParameters params = new PKIXParameters(truststore);
		
		// Activate certificate revocation checking
        params.setRevocationEnabled(true);

        // Activate OCSP
        Security.setProperty("ocsp.enable", "true");

        // Activate CRLDP
        System.setProperty("com.sun.security.enableCRLDP", "true");

        // Ensure that the ocsp.responderURL property is not set.
		if (Security.getProperty("ocsp.responderURL") != null) {
			throw new Exception("The ocsp.responderURL property must not be set");
		}

		CertPathValidator cpv = CertPathValidator.getInstance(CertPathValidator.getDefaultType());

		cpv.validate(CertificateFactory.getInstance("X.509").generateCertPath(certlist), params);

		return true; // No Exception, all fine..
	}
	
	/**
	 * Checks that the certificate is currently valid. It is if the current date and time are within the validity period given in the certificate.
	 * 
	 * @return true if certificate is currently valid, false otherwise.
	 */
	private boolean isCertCurrentlyValid() {
		try {
			signerCert.checkValidity();
			return true;
		} catch (CertificateExpiredException e) {
			e.printStackTrace();
		} catch (CertificateNotYetValidException e) {
			e.printStackTrace();
		}
		return false;
	}
	
	/**
	 * Returns the standard algorithm name for the public key.
	 * 
	 * @return Standard Algorithm of the public key
	 */
	private String getAlgo() {
		return signerCert.getPublicKey().getAlgorithm();
	}

	/**
	 * Gets the serialNumber value from the certificate. The serial number is an integer assigned by the certification authority to each certificate. It must be
	 * unique for each certificate issued by a given CA (i.e., the issuer name and serial number identify a unique certificate).
	 * 
	 * @return the serial number.
	 */
	private BigInteger getX509SerialNumber() {
		return signerCert.getSerialNumber();
	}

	/**
	 * Gets the subject (subject distinguished name) value from the certificate.
	 * 
	 * @return a Principal whose name is the subject name.
	 */
	private Principal getX509SubjectDN() {
		return signerCert.getSubjectDN();
	}

	/**
	 * Gets the issuer (issuer distinguished name) value from the certificate.
	 * 
	 * @return a Principal whose name is the issuer distinguished name.
	 */
	private Principal getX509IssuerDN() {
		return signerCert.getIssuerDN();
	}

	/**
	 * Gets the notBefore date from the validity period of the certificate.
	 * 
	 * @return the start date of the validity period.
	 */
	private Date getX509NotBefore() {
		return signerCert.getNotBefore();
	}

	/**
	 * Gets the notAfter date from the validity period of the certificate.
	 * 
	 * @return the end date of the validity period.
	 */
	private Date getX509NotAfter() {
		return signerCert.getNotAfter();
	}

	/**
	 * Get the user's unique Mobile ID SerialNumber from the signer certificate's SubjectDN
	 * 
	 * @return the user's unique Mobile ID serial number.
	 */
	private String getMIDSerialNumber() {
		Pattern pattern = Pattern.compile(".*SERIALNUMBER=(.{16}).*");
		Matcher matcher = pattern.matcher(signerCert.getSubjectDN().getName().toUpperCase());
		matcher.find();
		return matcher.group(1);
	}

	/**
	 * Get signed content - should be equal to the DTBS Message of the origin Signature Request
	 * 
	 * @return the signed data.
	 */
	private String getSignedData() {
		return new String((byte[]) cmsSignedData.getSignedContent().getContent()).toString();
	}

	/**
	 * Verify the signature on the SignerInformation object
	 * 
	 * @return true if the signer information is verified, false otherwise.
	 * @throws OperatorCreationException
	 * @throws CMSException
	 * @throws CertificateException 
	 */
	private boolean isVerified() throws OperatorCreationException, CMSException, CertificateException {
		Security.addProvider(new BouncyCastleProvider());
		return signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(x509CertHolder));
	}

}
