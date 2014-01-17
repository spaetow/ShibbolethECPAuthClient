/*******************************************************************************
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Portions of this code have been contributed by different parties:
 *
 * Copyright 2013 Ubiquitous Knowledge Processing (UKP) Lab.
 * Technische Universität Darmstadt.
 * All rights reserved.
 *
 * Copyright 2013 Diamond Light Source Ltd.
 * All rights reserved.
 *
 ******************************************************************************/

package uk.ac.diamond.shibbolethecpauthclient;

import static uk.ac.diamond.shibbolethecpauthclient.Utils.xmlToString;

import java.io.IOException;
import java.util.List;

import javax.security.sasl.AuthenticationException;

import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.soap.client.SOAPClientException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.Base64;

import de.tudarmstadt.ukp.shibhttpclient.ShibHttpClient;

/**
 * Implementation of an authentication client that uses the Shibboleth
 * ECP profile to use out-of-band means to authenticate a user against
 * a Shibboleth Identity Provider. Currently requires web endpoint 
 * protected by a Shibboleth Service Provider to function.
 *
 * @author Stefan Paetow
 * @since 1.0
 */
public class ShibbolethECPAuthClient extends ShibHttpClient {

	/** The logger instance */
	private static final Logger log = Logger.getLogger(ShibbolethECPAuthClient.class);

	/** The Shibboleth Identity Provider to use for authentication */
	private String IdP;

	/** The Shibboleth-protected web endpoint used for initiation of authentication */
	private String SP;

	/**
	 * @param proxy The proxy to initialize this client with. All connections will be proxied
	 *  through this host 
	 * @param idpURL The full ECP Profile URL of the Shibboleth Identity Provider
	 * @param spURL The URL to connect to to initiate the authentication process
	 * @param anyCert If true, disables certificate verification. Used generally with 
	 *  self-signed certificates
	 * 
	 * @throws ConfigurationException
	 * thrown if SAML is not able to initialize properly
	 * @throws IllegalStateException
	 * thrown if there is another problem
	 */
	public ShibbolethECPAuthClient(HttpHost proxy, String idpURL, String spURL, boolean anyCert) 
			throws ConfigurationException, IllegalStateException {

		// No need for IdP, username or password. They're only required for transparent auth, which we don't do 
		super(null, null, null, proxy, anyCert, false);
		this.IdP = idpURL;
		this.SP = spURL;
	}

	/**
	 * @param idpURL The full ECP Profile URL of the Shibboleth Identity Provider
	 * @param spURL The URL to connect to to initiate the authentication process
	 * @param anyCert If true, disables certificate verification. Used generally with 
	 *  self-signed certificates
	 * 
	 * @throws ConfigurationException
	 * thrown if SAML is not able to initialize properly
	 * @throws IllegalStateException
	 * thrown if there is another problem
	 */
	public ShibbolethECPAuthClient(String idpURL, String spURL, boolean anyCert) 
			throws ConfigurationException, IllegalStateException {
		this(null, idpURL, spURL, anyCert);
	}

	/**
	 * Attempts to authenticate the user and password against the IdP and SP this client
	 * was initialized with. 
	 * 
	 * @param username The username on the IdP to authenticate
	 * @param password The password to authenticate the username with
	 * @return A SAML Response from the Identity Provider
	 * 
	 * @throws IOException
	 * thrown if the client encounters a problem
	 * @throws AuthenticationException
	 * thrown if the client could not authenticate the username + password
	 * @throws SOAPClientException
	 * thrown if either Service Provider or Identity Provider are not configured for ECP
	 */
	@SuppressWarnings("deprecation")
	public org.opensaml.saml2.core.Response authenticate(String username, String password)
			throws IOException, AuthenticationException, SOAPClientException {

		// -- Connecting to SP, defer processing to parent class ------------------------------
		HttpResponse res = super.execute(new HttpGet(SP));
		log.info("Status: " + res.getStatusLine());
		for (Header h:res.getAllHeaders()) {
			log.debug(h.getName() + ": " + h.getValue());
		}
		String entity = EntityUtils.toString(res.getEntity());  // Warning: This closes the getEntity() InputStream!!
		log.debug("HttpResponse::Content: " + entity);

		if (!isSamlSoapResponse(res)) {
			throw new SOAPClientException("Service Provider not configured to accept ECP messages");
		}

		// -- Parse PAOS response -------------------------------------------------------------
		Envelope initialLoginSoapResponse = getSoapMessage(new StringEntity(entity)); // turn the string back into an entity

		// -- Pass the SOAP request from the SP to the IdP ------------------------------------
		Envelope idpLoginSoapRequest = new EnvelopeBuilder().buildObject();
		Body b = initialLoginSoapResponse.getBody();
		b.detach();
		idpLoginSoapRequest.setBody(b);

		// -- Try logging in to the IdP using HTTP BASIC authentication -----------------------
		log.debug("Logging into IdP [" + IdP + "]");
		HttpPost idpLoginRequest = new HttpPost(IdP);
		// Use the parent's AUTH_IN_PROGRESS string because it manages the pre-processing of a HTTP request
		idpLoginRequest.getParams().setBooleanParameter(super.getAuthInProgress(), true);
		idpLoginRequest.addHeader(HttpHeaders.AUTHORIZATION,
				"Basic " + Base64.encodeBytes((username + ":" + password).getBytes()));
		idpLoginRequest.setEntity(new StringEntity(xmlToString(idpLoginSoapRequest)));
		HttpResponse idpLoginResponse = super.execute(idpLoginRequest);

		// -- Handle HTTP log-in response from the IdP ----------------------------------------
		log.debug("Status: " + idpLoginResponse.getStatusLine());
		if (idpLoginResponse.getStatusLine().getStatusCode() != 200) {
			throw new AuthenticationException(idpLoginResponse.getStatusLine().toString());
		}

		String idpEntity = EntityUtils.toString(idpLoginResponse.getEntity()); // Warning: This closes the getEntity() InputStream!!
		log.debug("HttpResponse::Content: " + idpEntity);

		// -- Parse SAML SOAP response from the IdP -------------------------------------------
		Envelope idpLoginSoapResponse = getSoapMessage(new StringEntity(idpEntity)); // turn the string back into an entity
		
		// Get the consumer service URL (should be the SP's SOAP/ECP access point - we should check)
		String assertionConsumerServiceURL = ((org.opensaml.saml2.ecp.Response) idpLoginSoapResponse.getHeader()
				.getUnknownXMLObjects(org.opensaml.saml2.ecp.Response.DEFAULT_ELEMENT_NAME).get(0))
				.getAssertionConsumerServiceURL();
		log.debug("assertionConsumerServiceURL: " + assertionConsumerServiceURL);

		// SAML will only use the first response in a SOAP message
		List<XMLObject> responses = idpLoginSoapResponse.getBody().getUnknownXMLObjects(
				Response.DEFAULT_ELEMENT_NAME);
		if (!responses.isEmpty()) {
			Response response = (Response) responses
					.get(0);

			// Get root code (?)
			StatusCode sc = response.getStatus().getStatusCode();
			while (sc.getStatusCode() != null) {
				sc = sc.getStatusCode();
			}

			// Hm, they don't like us
			if (StatusCode.AUTHN_FAILED_URI.equals(sc.getValue())) {
				throw new AuthenticationException(sc.getValue());
			}

			// return the SAML response we got
			return response;
		}

		return null;
	}
}
