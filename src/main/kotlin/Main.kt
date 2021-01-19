import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import java.io.ByteArrayInputStream
import java.io.FileInputStream
import java.io.InputStreamReader
import java.security.KeyStore
import java.security.Security
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

import java.text.SimpleDateFormat
import java.util.*
import javax.net.ssl.*
import javax.net.ssl.SSLParameters

class Main {
    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            Security.addProvider(BouncyCastleProvider())
            val main = Main()
            val sslContext = main.getSocketFactoryPEM(
                "/Users/explorer/git/github/opsmx/oes-birger/deploy-sample/minica/minica.pem",
                "/Users/explorer/git/github/opsmx/oes-birger/deploy-sample/minica/oes-command/cert.pem",
                "/Users/explorer/git/github/opsmx/oes-birger/deploy-sample/minica/oes-command/key.pem")

            val sslSocketFactory = sslContext.socketFactory

            val socket = sslSocketFactory.createSocket("controller-command.svc.rpi.flame.org", 9003) as SSLSocket
            socket.soTimeout = 10000
            val params = SSLParameters()
            params.protocols = arrayOf("TLSv1.2") // force TLSv1.2 because Java has a broken implementation of v1.3 currently.
            socket.setSSLParameters(params)
            try {
                println("Starting SSL handshake...")
                socket.startHandshake()
                socket.close()
                println()
                println("No errors, certificate is already trusted")
            } catch (e: SSLException) {
                println()
                e.printStackTrace(System.out)
            }
        }
    }

    fun getSocketFactoryPEM(caCertificatePath: String, certificatePath: String, keyPath: String): SSLContext {
        val seq = ASN1Sequence.getInstance(readPEMFile(keyPath))
        val bcPrivateKey = RSAPrivateKey.getInstance(seq)
        val converter = JcaPEMKeyConverter()
        val algId = AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)
        val key = converter.getPrivateKey(PrivateKeyInfo(algId, bcPrivateKey))

        val cert = generateCertificateFromDER(readPEMFile(certificatePath))

        val caCert = generateCertificateFromDER(readPEMFile(caCertificatePath))

        val keystorePassword = "changeit".toCharArray()

        val keystore = KeyStore.getInstance("JKS")
        keystore.load(null)
        keystore.setCertificateEntry("oes-command", cert)
        keystore.setKeyEntry("oes-command", key, keystorePassword, arrayOf(cert, caCert))

        val kmf = KeyManagerFactory.getInstance("SunX509")
        kmf.init(keystore, keystorePassword)
        val km = kmf.keyManagers

        val truststore = KeyStore.getInstance("JKS")
        truststore.load(null)
        truststore.setEntry("ca-cert", KeyStore.TrustedCertificateEntry(caCert), null)

        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(truststore);

        val context = SSLContext.getInstance("TLS")
        context.init(km, tmf.trustManagers, null)

        return context
    }

    private fun generateCertificateFromDER(certBytes: ByteArray): X509Certificate {
        val factory = CertificateFactory.getInstance("X.509")
        return factory.generateCertificate(ByteArrayInputStream(certBytes)) as X509Certificate
    }

    private fun readPEMFile(filename: String): ByteArray {
        val pemReader = PemReader(InputStreamReader(FileInputStream(filename)))
        val pemObject : PemObject
        try {
            pemObject = pemReader.readPemObject()
        } finally {
            pemReader.close()
        }
        return pemObject.content
    }

}
