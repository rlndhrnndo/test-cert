package com.rlnd.sample;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.HttpHost;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import static java.util.regex.Pattern.CASE_INSENSITIVE;

@RestController()
public class TestCertController {

    public static final String KEY_STORE_TYPE_PKCS12 = "PKCS12";

    final static Pattern KEY_PATTERN = Pattern.compile(
            "-----BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+" + // Header
                    "([a-z0-9+/=\\r\\n]+)" +                       // Base64 text
                    "-+END\\s+.*PRIVATE\\s+KEY[^-]*-+",            // Footer
            CASE_INSENSITIVE);

    private static KeyStore createKeyStore() {
		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null, null);
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException
				| IOException ex) {
			throw new RuntimeException("Error creating the KeyStore", ex);
		}
		return keyStore;
	}

    /**
     * This assumes that there are no passwords on the private key
     * 
     * @param keyStream
     * @return
     * @throws Exception
     */
    private static PrivateKey generatePrivateKey(final InputStream keyStream) throws Exception {
        final var keyText = new String(keyStream.readAllBytes(), StandardCharsets.UTF_8);
        PrivateKey key = null;
        var matcher = KEY_PATTERN.matcher(keyText);
        if (!matcher.find()) {
            throw new KeyStoreException("Key not found");
        }
        var encodedKeySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(matcher.group(1).getBytes(StandardCharsets.US_ASCII)));
        var keyFactory = KeyFactory.getInstance("RSA");
        key = keyFactory.generatePrivate(encodedKeySpec);
        return key;
    }

    private static SSLContext createSSLContext() throws Exception {
        final var pass = randomString(512).toCharArray();

        // load the key as a inputstream
        final var caStream = new FileInputStream(new File("src/main/resources/test_ca.cer"));
        final var certStream = new FileInputStream(new File("src/main/resources/cert.cer"));
        final var keyStream = new FileInputStream(new File("src/main/resources/private.key"));

        //generate certificates
        final var ca = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(caStream);
        final var cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(certStream);
        //generate key
        final var key = generatePrivateKey(keyStream);

        var sslContext = SSLContext.getInstance("TLS");

        var keyStore = createKeyStore();
        var c = new Certificate[1];
        c[0] = cert;
        var keyEntry = new PrivateKeyEntry(key, c);
        keyStore.setEntry("cert_key", keyEntry, new PasswordProtection(pass));

        var trustStore = createKeyStore();
        trustStore.setCertificateEntry("Test-CA", ca);

        var keyManagerFactory = KeyManagerFactory
                .getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, pass);

        var trustManagerFactory = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        sslContext.init(
                keyManagerFactory.getKeyManagers(),
                trustManagerFactory.getTrustManagers(),
                null);

        return sslContext;
    }

    private static RestClient initializeSecureRestClient() throws Exception {
        final var sslContext = createSSLContext();
        final var socketFactory = new SSLConnectionSocketFactory(sslContext);
        final var connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setSSLSocketFactory(socketFactory)
                .build();
        final var closeable = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setProxy(new HttpHost("localhost", 3128))
                .evictExpiredConnections().build();
        final var factory = new HttpComponentsClientHttpRequestFactory(closeable);
        return RestClient.builder().requestFactory(factory).build();
    }

    private static String randomString(int length) {
        var random = new SecureRandom();
        var bytes = new byte[length];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().encodeToString(bytes);
    }

    // RestClient without specifying a custom truststore
    // this works for Adoptium
    @GetMapping("/test")
    public static String test() {
        var client = RestClient.create();
        return client.get()
                .uri("https://jsonplaceholder.typicode.com/posts/1")
                .retrieve()
                .body(String.class);
    }

    @GetMapping("/test-ca")
    public String getMethodName() throws Exception {
        var token = "";
        var client = initializeSecureRestClient();
        return client.get()
                .uri("<url_that_needs_custom_truststore>")
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .body(String.class);
    }
    

}
