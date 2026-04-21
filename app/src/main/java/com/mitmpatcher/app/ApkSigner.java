package com.mitmpatcher.app;

import android.content.Context;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.jar.*;
import java.util.zip.*;

/**
 * V1 (JAR) APK signer.
 * Generates and caches a self-signed RSA key in the app's private storage,
 * then signs the given APK in-place producing a new file.
 */
public class ApkSigner {

    private static final String KEY_ALIAS  = "mitm_key";
    private static final String KEY_FILE   = "mitm_key.p12";
    private static final String KEY_PASS   = "mitmpatcher";

    private final Context ctx;

    public ApkSigner(Context ctx) { this.ctx = ctx; }

    public File sign(File unsignedApk) throws Exception {
        KeyStore ks = loadOrCreateKeyStore();
        PrivateKey pk = (PrivateKey) ks.getKey(KEY_ALIAS, KEY_PASS.toCharArray());
        Certificate cert = ks.getCertificate(KEY_ALIAS);

        File signedApk = new File(ctx.getCacheDir(), "signed_" + unsignedApk.getName());
        signJar(unsignedApk, signedApk, pk, (X509Certificate) cert);
        return signedApk;
    }

    // -----------------------------------------------------------------------
    // V1 JAR signing
    // -----------------------------------------------------------------------

    private void signJar(File input, File output, PrivateKey pk, X509Certificate cert)
            throws Exception {

        // Phase 1: build MANIFEST.MF digests
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(new Attributes.Name("Created-By"), "MitmPatcher");

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        ZipFile zf = new ZipFile(input);
        Map<String, byte[]> entryData = new LinkedHashMap<>();

        Enumeration<? extends ZipEntry> entries = zf.entries();
        while (entries.hasMoreElements()) {
            ZipEntry ze = entries.nextElement();
            if (ze.getName().startsWith("META-INF/")) continue;
            byte[] data = readEntry(zf, ze);
            entryData.put(ze.getName(), data);
            sha256.reset();
            byte[] digest = sha256.digest(data);
            Attributes attrs = new Attributes();
            attrs.putValue("SHA-256-Digest", Base64.getEncoder().encodeToString(digest));
            manifest.getEntries().put(ze.getName(), attrs);
        }
        zf.close();

        // Serialize MANIFEST.MF
        ByteArrayOutputStream mfBaos = new ByteArrayOutputStream();
        manifest.write(mfBaos);
        byte[] mfBytes = mfBaos.toByteArray();

        // Phase 2: build CERT.SF (digest of manifest + each section)
        sha256.reset();
        byte[] mfDigest = sha256.digest(mfBytes);
        StringBuilder sf = new StringBuilder();
        sf.append("Signature-Version: 1.0\r\n");
        sf.append("SHA-256-Digest-Manifest: ")
          .append(Base64.getEncoder().encodeToString(mfDigest)).append("\r\n");
        sf.append("Created-By: MitmPatcher\r\n\r\n");

        for (Map.Entry<String, Attributes> e : manifest.getEntries().entrySet()) {
            String entrySection = e.getKey() + "\r\nSHA-256-Digest: "
                    + e.getValue().getValue("SHA-256-Digest") + "\r\n\r\n";
            sha256.reset();
            byte[] sectionDigest = sha256.digest(entrySection.getBytes("UTF-8"));
            sf.append("Name: ").append(e.getKey()).append("\r\n");
            sf.append("SHA-256-Digest: ")
              .append(Base64.getEncoder().encodeToString(sectionDigest)).append("\r\n\r\n");
        }
        byte[] sfBytes = sf.toString().getBytes("UTF-8");

        // Phase 3: sign CERT.SF → CERT.RSA (PKCS#7 / CMS detached signature)
        byte[] sigBytes = signData(sfBytes, pk, cert);

        // Phase 4: write output ZIP with META-INF
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(output))) {
            zos.setLevel(0); // store (no compression) for signing compatibility
            // Write original entries
            for (Map.Entry<String, byte[]> e : entryData.entrySet()) {
                ZipEntry ze = new ZipEntry(e.getKey());
                zos.putNextEntry(ze);
                zos.write(e.getValue());
                zos.closeEntry();
            }
            // META-INF/MANIFEST.MF
            ZipEntry mf = new ZipEntry("META-INF/MANIFEST.MF");
            zos.putNextEntry(mf);
            zos.write(mfBytes);
            zos.closeEntry();
            // META-INF/CERT.SF
            ZipEntry sfEntry = new ZipEntry("META-INF/CERT.SF");
            zos.putNextEntry(sfEntry);
            zos.write(sfBytes);
            zos.closeEntry();
            // META-INF/CERT.RSA
            ZipEntry rsaEntry = new ZipEntry("META-INF/CERT.RSA");
            zos.putNextEntry(rsaEntry);
            zos.write(sigBytes);
            zos.closeEntry();
        }
    }

    /** Build a minimal PKCS#7 DER block wrapping the SHA256withRSA signature. */
    private byte[] signData(byte[] data, PrivateKey pk, X509Certificate cert) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(pk);
        sig.update(data);
        byte[] rawSig = sig.sign();

        // Wrap in minimal PKCS#7 SignedData structure
        byte[] certBytes = cert.getEncoded();
        return buildPkcs7(rawSig, certBytes, cert);
    }

    /** Minimal PKCS#7 / CMS SignedData for APK V1 signing. */
    private byte[] buildPkcs7(byte[] signature, byte[] certDer, X509Certificate cert) throws Exception {
        // We build a proper (if minimal) PKCS#7 SignedData using Android's available classes.
        // Using sun.security.pkcs is available on Android's JVM.
        // Fallback: construct DER manually.
        // For simplicity, use a pre-built template approach via the standard JCE.
        // Android doesn't expose PKCS7 in public APIs, so use the BouncyCastle-lite path:
        return buildPkcs7Manual(signature, certDer, cert);
    }

    private byte[] buildPkcs7Manual(byte[] sig, byte[] certDer, X509Certificate cert)
            throws Exception {
        // Minimal PKCS#7 SignedData DER structure accepted by Android's APK installer
        // OID 1.2.840.113549.1.7.2 = signedData
        byte[] issuerAndSerial = buildIssuerAndSerial(cert);
        byte[] sha256OidBytes = derOid(new int[]{2,16,840,1,101,3,4,2,1}); // SHA-256
        byte[] rsaOidBytes    = derOid(new int[]{1,2,840,113549,1,1,1});    // RSA

        // signerInfo
        ByteArrayOutputStream si = new ByteArrayOutputStream();
        si.write(derInt(1));                              // version 1
        si.write(issuerAndSerial);                        // issuerAndSerialNumber
        si.write(derSequence(sha256OidBytes, derNull())); // digestAlgorithm
        si.write(derSequence(rsaOidBytes, derNull()));    // signatureAlgorithm
        si.write(derOctetString(sig));                    // signature
        byte[] signerInfo = derSequence(si.toByteArray());

        // signedData content
        ByteArrayOutputStream sd = new ByteArrayOutputStream();
        sd.write(derInt(1));                              // version
        // digestAlgorithms SET
        sd.write(derSet(derSequence(sha256OidBytes, derNull())));
        // contentInfo (detached: no content)
        sd.write(derSequence(derOid(new int[]{1,2,840,113549,1,7,1}))); // data OID
        // certificates [0] IMPLICIT
        sd.write(derTag(0xA0, certDer));
        // signerInfos SET
        sd.write(derSet(signerInfo));

        byte[] signedData = derSequence(sd.toByteArray());

        // Outer ContentInfo
        ByteArrayOutputStream ci = new ByteArrayOutputStream();
        ci.write(derOid(new int[]{1,2,840,113549,1,7,2}));
        ci.write(derTag(0xA0, signedData));
        return derSequence(ci.toByteArray());
    }

    private byte[] buildIssuerAndSerial(X509Certificate cert) throws Exception {
        byte[] issuer = cert.getIssuerX500Principal().getEncoded();
        byte[] serial = derInt(cert.getSerialNumber().intValue());
        return derSequence(issuer, serial);
    }

    // DER helpers
    private static byte[] derTag(int tag, byte[] content) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        writeLength(out, content.length);
        out.write(content);
        return out.toByteArray();
    }
    private static byte[] derSequence(byte[]... parts) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] p : parts) body.write(p);
        return derTag(0x30, body.toByteArray());
    }
    private static byte[] derSet(byte[]... parts) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] p : parts) body.write(p);
        return derTag(0x31, body.toByteArray());
    }
    private static byte[] derOid(int[] components) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(components[0] * 40 + components[1]);
        for (int i = 2; i < components.length; i++) {
            int v = components[i];
            if (v < 0x80) { body.write(v); }
            else {
                List<Integer> bytes = new ArrayList<>();
                bytes.add(v & 0x7F);
                v >>= 7;
                while (v > 0) { bytes.add((v & 0x7F) | 0x80); v >>= 7; }
                Collections.reverse(bytes);
                for (int b : bytes) body.write(b);
            }
        }
        return derTag(0x06, body.toByteArray());
    }
    private static byte[] derInt(int v) throws IOException {
        byte[] bytes = BigInteger.valueOf(v).toByteArray();
        return derTag(0x02, bytes);
    }
    private static byte[] derNull()         throws IOException { return derTag(0x05, new byte[0]); }
    private static byte[] derOctetString(byte[] d) throws IOException { return derTag(0x04, d); }
    private static void writeLength(OutputStream out, int len) throws IOException {
        if (len < 128) { out.write(len); }
        else if (len < 256) { out.write(0x81); out.write(len); }
        else { out.write(0x82); out.write((len >> 8) & 0xFF); out.write(len & 0xFF); }
    }

    // -----------------------------------------------------------------------
    // Key store
    // -----------------------------------------------------------------------

    private KeyStore loadOrCreateKeyStore() throws Exception {
        File ksFile = new File(ctx.getFilesDir(), KEY_FILE);
        // PKCS12 is available on all Android versions without a specific provider
        KeyStore ks = KeyStore.getInstance("PKCS12");

        if (ksFile.exists()) {
            try (InputStream is = new FileInputStream(ksFile)) {
                ks.load(is, KEY_PASS.toCharArray());
                if (ks.containsAlias(KEY_ALIAS)) return ks;
            } catch (Exception ignored) {}
        }

        // Generate new key pair
        ks.load(null, KEY_PASS.toCharArray());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = generateSelfSignedCert(kp);
        ks.setKeyEntry(KEY_ALIAS, kp.getPrivate(), KEY_PASS.toCharArray(),
                new Certificate[]{cert});

        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            ks.store(fos, KEY_PASS.toCharArray());
        }
        return ks;
    }

    @SuppressWarnings("deprecation")
    private X509Certificate generateSelfSignedCert(KeyPair kp) throws Exception {
        // Use sun.security.x509 which is available on Android's JVM
        try {
            Class<?> certInfoClass = Class.forName("sun.security.x509.X509CertInfo");
            Class<?> certClass     = Class.forName("sun.security.x509.X509CertImpl");
            Class<?> x500NameClass = Class.forName("sun.security.x509.X500Name");
            Class<?> validityClass = Class.forName("sun.security.x509.CertificateValidity");
            Class<?> snClass       = Class.forName("sun.security.x509.CertificateSerialNumber");
            Class<?> algIdClass    = Class.forName("sun.security.x509.AlgorithmId");
            Class<?> algParamClass = Class.forName("sun.security.x509.CertificateAlgorithmId");
            Class<?> subjClass     = Class.forName("sun.security.x509.CertificateSubjectName");
            Class<?> issuerClass   = Class.forName("sun.security.x509.CertificateIssuerName");
            Class<?> keyClass      = Class.forName("sun.security.x509.CertificateX509Key");

            Object x500Name = x500NameClass.getConstructor(String.class).newInstance("CN=MitmPatcher");
            Date from = new Date();
            Date to   = new Date(from.getTime() + 30L * 365 * 24 * 60 * 60 * 1000);
            Object validity = validityClass.getConstructor(Date.class, Date.class).newInstance(from, to);
            Object sn       = snClass.getConstructor(BigInteger.class).newInstance(BigInteger.ONE);
            Object algId    = algIdClass.getMethod("get", String.class).invoke(null, "SHA256withRSA");
            Object algParam = algParamClass.getConstructor(algIdClass).newInstance(algId);
            Object subj     = subjClass.getConstructor(x500NameClass).newInstance(x500Name);
            Object issuer   = issuerClass.getConstructor(x500NameClass).newInstance(x500Name);
            Object key      = keyClass.getConstructor(PublicKey.class).newInstance(kp.getPublic());

            Object info = certInfoClass.newInstance();
            certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "validity", validity);
            certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "serialNumber", sn);
            certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "subject", subj);
            certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "issuer", issuer);
            certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "key", key);
            certInfoClass.getMethod("set", String.class, Object.class).invoke(info, "algorithmID", algParam);

            Object cert = certClass.getConstructor(certInfoClass).newInstance(info);
            certClass.getMethod("sign", PrivateKey.class, String.class)
                    .invoke(cert, kp.getPrivate(), "SHA256withRSA");
            return (X509Certificate) cert;
        } catch (Exception e) {
            throw new RuntimeException("Could not generate self-signed certificate: " + e.getMessage(), e);
        }
    }

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    private static byte[] readEntry(ZipFile zf, ZipEntry ze) throws IOException {
        try (InputStream is = zf.getInputStream(ze)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) out.write(buf, 0, n);
            return out.toByteArray();
        }
    }
}
