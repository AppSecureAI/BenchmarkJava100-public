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
 * @author Nick Sanidas
 * @created 2015
 */
package org.owasp.benchmark.testcode;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/cmdi-00/BenchmarkTest00302")
public class BenchmarkTest00302 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    // Explicit allowlist of the only command this endpoint is permitted to invoke.
    private static final java.util.Map<String, String> ALLOWED_COMMANDS =
            java.util.Collections.singletonMap("echo", "echo");

    // Narrow allowlist tied to the supported command grammar: the echoed value may
    // only contain alphanumerics, spaces, and a small set of benign punctuation.
    // Any shell metacharacter (&, |, ;, <, >, ^, %, quotes, etc.) is rejected so it
    // can never be interpreted by the Windows cmd.exe wrapper required to invoke the
    // built-in echo command.
    private static final java.util.regex.Pattern SAFE_ARG_PATTERN =
            java.util.regex.Pattern.compile("^[a-zA-Z0-9 ._-]*$");

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00302");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String bar;

        // Simple ? condition that assigns param to bar on false condition
        int num = 106;

        bar = (7 * 42) - num > 200 ? "This should never happen" : param;

        // Fail closed: on Windows, echo is a cmd.exe built-in, so cmd.exe /c must be
        // used to invoke it and the trailing argument is parsed by that shell rather
        // than passed as an isolated argv element. Constrain the shell-consumed value
        // to the narrow allowlisted grammar this endpoint actually supports (a plain
        // echoed value) before it is ever added to the command; anything containing
        // shell metacharacters is replaced with the safe empty default instead of
        // reaching the shell.
        if (!SAFE_ARG_PATTERN.matcher(bar).matches()) {
            bar = "";
        }

        java.util.List<String> argList = new java.util.ArrayList<String>();
        String osName = System.getProperty("os.name");
        String echoCommand = ALLOWED_COMMANDS.get("echo");
        if (osName.indexOf("Windows") != -1) {
            argList.add("cmd.exe");
            argList.add("/c");
            argList.add(echoCommand);
        } else {
            argList.add(echoCommand);
        }
        argList.add(bar);

        ProcessBuilder pb = new ProcessBuilder(argList);

        try {
            Process p = pb.start();
            org.owasp.benchmark.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println("Problem executing cmdi - TestCase");
            response.getWriter()
                    .println(org.owasp.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
            return;
        }
    }
}
