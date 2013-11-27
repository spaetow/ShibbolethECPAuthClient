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

import static java.util.Arrays.asList;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.ProxySelector;
import java.security.GeneralSecurityException;
import java.util.List;

import javax.security.sasl.AuthenticationException;

import org.apache.log4j.Logger;
import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestWrapper;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.impl.conn.SystemDefaultRoutePlanner;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.ecp.Response;
import org.opensaml.ws.soap.client.SOAPClientException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.ws.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.util.Base64;

public class ShibbolethECPAuthClient {

    private static final Logger log = Logger.getLogger(ShibbolethECPAuthClient.class);

    private static final String AUTH_IN_PROGRESS = ShibbolethECPAuthClient.class.getName()
            + ".AUTH_IN_PROGRESS";

    private static final String MIME_TYPE_PAOS = "application/vnd.paos+xml";

    private static final String HEADER_AUTHORIZATION = "Authorization";

    private static final String HEADER_CONTENT_TYPE = "Content-Type";

    private static final String HEADER_ACCEPT = "Accept";

    private static final String HEADER_PAOS = "PAOS";

    private CloseableHttpClient client;

    private BasicCookieStore cookieStore;

    private String IdP;

    private String SP;

    private BasicParserPool parserPool;
    
    private HttpHost proxyHost;

    private static final List<String> REDIRECTABLE = asList("HEAD", "GET");

    public ShibbolethECPAuthClient(HttpHost proxy, String idpURL, String spURL, boolean anyCert) 
            throws ConfigurationException, IllegalStateException
    {
    	setIDP(idpURL);
        setSP(spURL);
        setProxy(proxy);

        // Use a pooling connection manager, because we'll have to do a call out to the IdP
        // while still being in a connection with the SP
        PoolingHttpClientConnectionManager connMgr;
        if (anyCert) {
            try {
                SSLContextBuilder builder = new SSLContextBuilder();
                builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
                SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build());
                PlainConnectionSocketFactory plainsf = new PlainConnectionSocketFactory();
                Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder
                        .<ConnectionSocketFactory> create()
                        .register("http", plainsf)
                        .register("https", sslsf)
                        .build();
                connMgr = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
            }
            catch (GeneralSecurityException e) {
                // There shouldn't be any of these exceptions, because we do not use an actual keystore
                throw new IllegalStateException(e);
            }
        }
        else {
            connMgr = new PoolingHttpClientConnectionManager();
        }
        connMgr.setMaxTotal(10);
        connMgr.setDefaultMaxPerRoute(5);

        // retrieve the JVM parameters for proxy state (do we have a proxy?)
        SystemDefaultRoutePlanner sdrp = new SystemDefaultRoutePlanner(ProxySelector.getDefault());

        // The client needs to remember the auth cookie
        cookieStore = new BasicCookieStore();
        RequestConfig globalRequestConfig = RequestConfig.custom()
                .setCookieSpec(CookieSpecs.BROWSER_COMPATIBILITY)
                .build();

        // build our client
        if (proxyHost == null) {
            client = HttpClients.custom()
                    .setConnectionManager(connMgr)
                    // use the proxy settings of the JVM, if specified 
                    .setRoutePlanner(sdrp)
                    // The client needs to remember the auth cookie
                    .setDefaultRequestConfig(globalRequestConfig)
                    .setDefaultCookieStore(cookieStore)
                    // Add the ECP/PAOS headers - needs to be added first so the cookie we get from
                    // the authentication can be handled by the RequestAddCookies interceptor later
                    .addInterceptorFirst(new HttpRequestPreprocessor())
                    .build();
        }
        else {
            client = HttpClients.custom()
                    .setConnectionManager(connMgr)
                    // use the explicit proxy
                    .setProxy(proxyHost)
                    // The client needs to remember the auth cookie
                    .setDefaultRequestConfig(globalRequestConfig)
                    .setDefaultCookieStore(cookieStore)
                    // Add the ECP/PAOS headers - needs to be added first so the cookie we get from
                    // the authentication can be handled by the RequestAddCookies interceptor later
                    .addInterceptorFirst(new HttpRequestPreprocessor())
                    .build();
        }

        DefaultBootstrap.bootstrap();
        parserPool = new BasicParserPool();
        parserPool.setNamespaceAware(true);
    }

    public ShibbolethECPAuthClient(String idpURL, String spURL, boolean anyCert) 
            throws ConfigurationException, IllegalStateException
    {
    	this(null, idpURL, spURL, true);
    }

    private void setIDP(String idpURL) {
        IdP = idpURL;
    }

    private void setSP(String spURL) {
        SP = spURL;
    }

    private void setProxy(HttpHost proxy) {
        proxyHost = proxy;
    }

    @SuppressWarnings("deprecation")
    public org.opensaml.saml2.core.Response authenticate(String username, String password)
            throws IOException, AuthenticationException, SOAPClientException
    {
        HttpGet req = new HttpGet(SP);
        try {
            HttpResponse res = client.execute(req);
            log.info("HttpResponse::Status: " + res.getStatusLine());
            log.debug("HttpResponse::res: " + res.toString());
            Header headers[] = res.getAllHeaders();
            for (Header h:headers) {
                log.debug(h.getName() + ": " + h.getValue());
            }
            String entity = EntityUtils.toString(res.getEntity());  // Warning: This closes the getEntity() InputStream!!
            log.debug("HttpResponse::Content: " + entity);

            boolean isSamlSoap = false;
            if (res.getFirstHeader(HEADER_CONTENT_TYPE) != null) {
                ContentType contentType = ContentType.parse(res.getFirstHeader(HEADER_CONTENT_TYPE)
                        .getValue());
                isSamlSoap = MIME_TYPE_PAOS.equals(contentType.getMimeType());
            }

            // We didn't receive a SOAP request back, so ECP is not enabled. This doesn't help us. Bail immediately!
            if (!isSamlSoap) {
                throw new SOAPClientException("Service Provider not configured to accept ECP messages");
            }

            // -- Parse PAOS response -------------------------------------------------------------
            Envelope initialLoginSoapResponse = (Envelope) Utils.unmarshallMessage(parserPool,
                    new ByteArrayInputStream(entity.getBytes())); // turn the string output of getEntity() back into InputStream

            log.debug("Logging into IdP [" + IdP + "]");
            Envelope idpLoginSoapRequest = new EnvelopeBuilder().buildObject();
            Body b = initialLoginSoapResponse.getBody();
            b.detach();
            idpLoginSoapRequest.setBody(b);

            // Try logging in to the IdP using HTTP BASIC authentication
            HttpPost idpLoginRequest = new HttpPost(IdP);
            idpLoginRequest.getParams().setBooleanParameter(AUTH_IN_PROGRESS, true);
            idpLoginRequest.addHeader(HEADER_AUTHORIZATION, "Basic " + Base64.encodeBytes((username + ":" + password).getBytes()));
            idpLoginRequest.setEntity(new StringEntity(Utils.xmlToString(idpLoginSoapRequest)));
            HttpResponse idpLoginResponse = client.execute(idpLoginRequest);

            // -- Handle log-in response from the IdP --------------------------------------------
            log.debug("Status: " + idpLoginResponse.getStatusLine());
            if (idpLoginResponse.getStatusLine().getStatusCode() != 200) {
                throw new AuthenticationException(idpLoginResponse.getStatusLine().toString());
            }
            
            String idpEntity = EntityUtils.toString(idpLoginResponse.getEntity()); // Warning: This closes the getEntity() InputStream!!
            log.debug("HttpResponse::Content: " + idpEntity);

            Envelope idpLoginSoapResponse = (Envelope) Utils.unmarshallMessage(parserPool,
                    new ByteArrayInputStream(idpEntity.getBytes())); // turn the string output of getEntity() back into InputStream
            EntityUtils.consume(idpLoginResponse.getEntity());
            String assertionConsumerServiceURL = ((Response) idpLoginSoapResponse.getHeader()
                    .getUnknownXMLObjects(Response.DEFAULT_ELEMENT_NAME).get(0))
                    .getAssertionConsumerServiceURL();
            log.debug("assertionConsumerServiceURL: " + assertionConsumerServiceURL);

            List<XMLObject> responses = idpLoginSoapResponse.getBody().getUnknownXMLObjects(
                    org.opensaml.saml2.core.Response.DEFAULT_ELEMENT_NAME);
            if (!responses.isEmpty()) {
                org.opensaml.saml2.core.Response response = (org.opensaml.saml2.core.Response) responses
                        .get(0);

                // Get root code (?)
                StatusCode sc = response.getStatus().getStatusCode();
                while (sc.getStatusCode() != null) {
                    sc = sc.getStatusCode();
                }

                // Hm, they don't like us
                if ("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed".equals(sc.getValue())) {
                    throw new AuthenticationException(sc.getValue());
                }

                // return the SAML response we got
                return response;
            }
        }
        finally {
            client.close();
        }
        
        return null;
    }
	
    /**
     * Add the ECP/PAOS headers to each outgoing request.
     */
    private final class HttpRequestPreprocessor
            implements HttpRequestInterceptor
    {
        @Override
        public void process(final HttpRequest req, final HttpContext ctx)
                throws HttpException, IOException
        {
            req.addHeader(HEADER_ACCEPT, MIME_TYPE_PAOS);
            req.addHeader(HEADER_PAOS, "ver=\"" + SAMLConstants.PAOS_NS + "\";\""
                    + SAMLConstants.SAML20ECP_NS + "\"");

            HttpRequest r = req;
            if (req instanceof HttpRequestWrapper) { // does not forward request to original
                r = ((HttpRequestWrapper) req).getOriginal();
            }

            // This request is not redirectable, so we better knock to see if authentication
            // is necessary.
            if (!REDIRECTABLE.contains(r.getRequestLine().getMethod())
                    && r.getParams().isParameterFalse(AUTH_IN_PROGRESS)) {
                log.trace("Unredirectable request [" + r.getRequestLine().getMethod()
                        + "], trying to knock first at " + r.getRequestLine().getUri());
                HttpHead knockRequest = new HttpHead(r.getRequestLine().getUri());
                client.execute(knockRequest);

                for (Cookie c : cookieStore.getCookies()) {
                    log.trace(c.toString());
                }
                log.trace("Knocked");
            }
        }
    }
}
