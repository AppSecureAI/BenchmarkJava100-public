/**
 * OWASP Benchmark Project v1.2
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project. For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @created 2015
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/hash-01/BenchmarkTest01334")
public class BenchmarkTest01334 extends HttpServlet {

    private static final long serialVersionUID = 1L;
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final byte[] SECRET_KEY = loadSecretKey();

    private static byte[] loadSecretKey() {
        String keyHex = System.getenv("HMAC_SECRET_KEY");
        if (keyHex == null || keyHex.isEmpty()) {
            throw new RuntimeException(
                    "HMAC_SECRET_KEY environment variable must be set with a hex-encoded 256-bit key. "
                    + "Generate one with: openssl rand -hex 32");
        }
        try {
            // Convert hex string to byte array
            int len = keyHex.length();
            if (len % 2 != 0) {
                throw new RuntimeException("HMAC_SECRET_KEY must be a valid hex string (even length)");
            }
            byte[] key = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                key[i / 2] = (byte) ((Character.digit(keyHex.charAt(i), 16) << 4)
                        + Character.digit(keyHex.charAt(i + 1), 16));
            }
            if (key.length < 32) {
                throw new RuntimeException("HMAC_SECRET_KEY must be at least 256 bits (64 hex characters)");
            }
            return key;
        } catch (NumberFormatException e) {
            throw new RuntimeException("HMAC_SECRET_KEY must be a valid hex string", e);
        }
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        java.util.Map<String, String[]> map = request.getParameterMap();
        String param = "";
        if (!map.isEmpty()) {
            String[] values = map.get("BenchmarkTest01334");
            if (values != null) param = values[0];
        }

        String bar = new Test().doSomething(request, param);

        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY, HMAC_ALGORITHM);
            mac.init(keySpec);

            byte[] input = {(byte) '?'};
            Object inputParam = bar;
            if (inputParam instanceof String) input = ((String) inputParam).getBytes();
            if (inputParam instanceof java.io.InputStream) {
                byte[] strInput = new byte[1000];
                int i = ((java.io.InputStream) inputParam).read(strInput);
                if (i == -1) {
                    response.getWriter()
                            .println(
                                    "This input source requires a POST, not a GET. Incompatible UI for the InputStream source.");
                    return;
                }
                input = java.util.Arrays.copyOf(strInput, i);
            }

            byte[] result = mac.doFinal(input);
            java.io.File fileTarget =
                    new java.io.File(
                            new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR),
                            "passwordFile.txt");
            java.io.FileWriter fw =
                    new java.io.FileWriter(fileTarget, true); // the true will append the new data
            fw.write(
                    "hash_value="
                            + org.owasp.esapi.ESAPI.encoder().encodeForBase64(result, true)
                            + "
");
            fw.close();
            response.getWriter()
                    .println(
                            "Sensitive value '"
                                    + org.owasp
                                            .esapi
                                            .ESAPI
                                            .encoder()
                                            .encodeForHTML(new String(input))
                                    + "' hashed and stored<br/>");

        } catch (java.security.NoSuchAlgorithmException | java.security.InvalidKeyException e) {
            System.out.println("Problem executing hash - TestCase");
            throw new ServletException(e);
        }

        response.getWriter()
                .println(
                        "Hash Test javax.crypto.Mac.getInstance(java.lang.String) executed");
    } // end doPost

    private class Test {

        public String doSomething(HttpServletRequest request, String param)
                throws ServletException, IOException {

            String bar = "alsosafe";
            if (param != null) {
                java.util.List<String> valuesList = new java.util.ArrayList<String>();
                valuesList.add("safe");
                valuesList.add(param);
                valuesList.add("moresafe");

                valuesList.remove(0); // remove the 1st safe value

                bar = valuesList.get(1); // get the last 'safe' value
            }

            return bar;
        }
    } // end innerclass Test
} // end DataflowThruInnerClass
