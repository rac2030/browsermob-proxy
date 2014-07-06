package net.lightbody.bmp.proxy.auth;

import net.lightbody.bmp.proxy.http.BrowserMobHttpClient;
import net.lightbody.bmp.proxy.http.TrustingSSLSocketFactory;
import org.apache.commons.io.FileUtils;
import org.jetbrains.annotations.NotNull;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Created by rac on 06.07.14.
 */
public class ClientCertAuth implements IAuthSSLContext {
    private File keyStoreFile;
    private File keyStorePwdFile;
    private String keyStoreType = "PKCS12";

    public ClientCertAuth(@NotNull File keyStoreFile, @NotNull File keyStorePwdFile, String keyStoreType) {
        this.keyStoreFile = keyStoreFile;
        this.keyStorePwdFile = keyStorePwdFile;
        this.keyStoreType = keyStoreType;
    }

    public SSLContext getSSLContext() {
        SSLContext ret;
        try {
            ret = SSLContext.getInstance(TrustingSSLSocketFactory.SSLAlgorithm.SSLv3.name());
            FileInputStream keyInput = FileUtils.openInputStream(keyStoreFile);
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            char[] keyStorePasswd = FileUtils.readFileToString(keyStorePwdFile).toCharArray();
            keyStore.load(keyInput, keyStorePasswd);
            keyInput.close();
            /** Create key manager **/
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, keyStorePasswd);
            KeyManager[] keyManagers = kmf.getKeyManagers();
            ret.init(keyManagers, new TrustManager[]{TrustingSSLSocketFactory.easyTrustManager}, new SecureRandom()); //TODO probably needs a safer way for random ;-)

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("TLS algorithm not found! Critical SSL error!", e);
        } catch (IOException e) {
            throw new RuntimeException("IO Problem reading keystore or pwd File! Critical SSL error!", e);
        } catch (KeyStoreException e) {
            throw new RuntimeException("KeyStore type problem! Critical SSL error!", e);
        } catch (CertificateException e) {
            throw new RuntimeException("Certificate Exception! Critical SSL error!", e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException("KeyManager init problem! Critical SSL error!", e);
        } catch (KeyManagementException e) {
            throw new RuntimeException("SSLContext init problem! Critical SSL error!", e);
        }

        return ret;
    }
}
