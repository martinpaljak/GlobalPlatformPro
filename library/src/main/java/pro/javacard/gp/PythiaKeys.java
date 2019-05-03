/*
 * GlobalPlatformPro - GlobalPlatform tool
 *
 * Copyright (C) 2015-2017 Martin Paljak, martin@martinpaljak.net
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package pro.javacard.gp;

import apdu4j.HexUtils;
import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import javax.net.ssl.*;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

// Knows keying information to access a card.
public class PythiaKeys {
    public static final String PYTHIA_URL = "https://javacard.pro/pythia";
    public static final OracleHint DEFAULT = makeDefault();

    private static PlaintextKeys fromHint(OracleHint hint) throws GPDataException {
        try {
            final PlaintextKeys r;
            if (hint.key != null && hint.algo != null) {
                r = PlaintextKeys.fromMasterKey(new GPKey(HexUtils.hex2bin(hint.key), GPKey.Type.valueOf(hint.algo)));
            } else if (hint.mac != null && hint.enc != null && hint.kek != null && hint.algo != null) {
                GPKey enc = new GPKey(HexUtils.hex2bin(hint.enc), GPKey.Type.valueOf(hint.algo));
                GPKey mac = new GPKey(HexUtils.hex2bin(hint.mac), GPKey.Type.valueOf(hint.algo));
                GPKey dek = new GPKey(HexUtils.hex2bin(hint.kek), GPKey.Type.valueOf(hint.algo));
                r = PlaintextKeys.fromKeys(enc, mac, dek);
            } else {
                throw new GPDataException("Oracle does not know the keys :(");
            }

            if (hint.div != null)
                r.setDiversifier(PlaintextKeys.Diversification.valueOf(hint.div));

            // TODO: version, id
            System.out.println("Using aid=" + hint.aid + " div=" + hint.div + " algo=" + hint.algo + " key=" + hint.key);
            return r;
        } catch (Exception e) {
            e.printStackTrace();
            throw new GPDataException("Failed: " + e.getMessage());
        }
    }

    // Ask Pythia for help, choosing from many possibilities.
    public static PlaintextKeys ask(byte[] atr, byte[] cplc, byte[] kinfo) throws GPDataException {
        try {
            // FIXME: not that OK for contactless, but ....
            String urlstring = PYTHIA_URL;
            urlstring += "?atr=" + HexUtils.bin2hex(atr);

            if (cplc != null && cplc.length > 0)
                urlstring += "&cplc=" + HexUtils.bin2hex(cplc);
            if (kinfo != null && kinfo.length > 0)
                urlstring += "&keys=" + HexUtils.bin2hex(kinfo);

            URL url = new URL(urlstring);

            SSLContext ssl = SSLContext.getInstance("TLSv1.2");
            ssl.init(null, new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                    throw new CertificateException("No client authentication required");
                }

                @Override
                public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                    if (x509Certificates.length < 1)
                        throw new CertificateException("No certificate");
                    try (InputStream cert = PythiaKeys.class.getResourceAsStream("javacard.pro.pem")) {
                        if (cert == null) {
                            throw new CertificateException("No certificate bundled");
                        }
                        CertificateFactory cf = CertificateFactory.getInstance("X509");
                        X509Certificate c = (X509Certificate) cf.generateCertificate(cert);
                        if (x509Certificates[0].equals(c)) {
                            return;
                        }
                    } catch (IOException e) {
                        // Ignore
                    }

                    throw new CertificateException("javacard.pro certificate not in server chain");
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    try (InputStream cert = PythiaKeys.class.getResourceAsStream("letsencrypt.pem")) {
                        if (cert != null) {
                            CertificateFactory cf = CertificateFactory.getInstance("X509");
                            X509Certificate c = (X509Certificate) cf.generateCertificate(cert);
                            return new X509Certificate[]{c};
                        }
                    } catch (CertificateException|IOException e) {
                        // Ignore
                    }
                    return new X509Certificate[0];
                }

            }
            }, null);
            SSLSocketFactory factory = ssl.getSocketFactory();
            HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
            con.setSSLSocketFactory(factory);
            con.setRequestProperty("User-Agent", "GlobalPlatformPro/" + GlobalPlatform.getVersion());

            OracleHint[] hints;
            try (InputStreamReader in = new InputStreamReader(con.getInputStream(), StandardCharsets.UTF_8)) {
                hints = new Gson().fromJson(in, OracleHint[].class);
                if (hints == null) {
                    throw new GPDataException("Pythia is confused, there are no hints");
                }
            } catch (SSLHandshakeException e) {
                throw new GPDataException("Can not establish a connection to Pythia");
            }

            if (hints.length > 1) {
                Console c = System.console();

                if (c != null) {
                    System.out.println("Pythia, the oracle, knows " + hints.length + " configurations for this card. Choose one");

                    int i = 0;
                    for (OracleHint h : hints) {
                        System.out.println(i + ": " + h.name);
                        i++;
                    }
                    while (true) {
                        String res = c.readLine("Make choice (0.." + (i - 1) + " or ctrl-c): ");
                        if (res == null) {
                            c.writer().println("Closing up");
                            System.exit(1);
                        } else {
                            int idx = Integer.parseInt(res);
                            if (idx < 0 || idx >= i) {
                                System.out.println("Wrong value, try again");
                            } else {
                                System.out.println("Chose " + hints[idx].name);
                                return fromHint(hints[idx]);
                            }
                        }
                    }
                } else {
                    System.err.println("Console not available but Pythia knows more than one card");
                    System.err.println("Returning first configuration");
                    return fromHint(hints[0]);
                }
            } else if (hints.length == 1) {
                // FIXME: ask for confirmation?
                return fromHint(hints[1]);
            } else {
                // FIXME: use default? Ask for confirmation
                return fromHint(DEFAULT);
            }
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            throw new GPDataException("Pythia is broken :( Use your own Wisdom!");
        }
    }

    private final static OracleHint makeDefault() {
        OracleHint DEFAULT = new OracleHint();
        DEFAULT.aid = HexUtils.bin2hex(GPData.defaultISDBytes);
        DEFAULT.key = HexUtils.bin2hex(GPData.defaultKeyBytes);
        DEFAULT.algo = GPKey.Type.DES3.name();
        return DEFAULT;
    }


    // For JSON parsing with Gson
    static class OracleHint {
        @SerializedName("name")
        String name;

        @SerializedName("aid")
        String aid;

        @SerializedName("key")
        String key;

        @SerializedName("enc")
        String enc;

        @SerializedName("mac")
        String mac;

        @SerializedName("kek")
        String kek;

        @SerializedName("div")
        String div;

        @SerializedName("algo")
        String algo;

        @SerializedName("id")
        String id;

        @SerializedName("ver")
        String ver;
    }
}
