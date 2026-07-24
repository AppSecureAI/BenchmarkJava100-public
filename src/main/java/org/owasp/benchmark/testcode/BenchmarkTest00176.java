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

@WebServlet(value = "/cmdi-00/BenchmarkTest00176")
public class BenchmarkTest00176 extends HttpServlet {

    private static final long serialVersionUID = 1L;

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
        if (request.getHeader("BenchmarkTest00176") != null) {
            param = request.getHeader("BenchmarkTest00176");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String bar = param;

        // Build a fixed, non-shell command vector so the user-supplied value can only ever be
        // consumed as a single literal argument to the "echo" executable, never as the
        // executable itself or as additional shell-interpreted tokens/commands.
        java.util.List<String> command = new java.util.ArrayList<String>();
        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            // "echo" is a cmd.exe builtin, so cmd.exe /c is unavoidable here. cmd.exe re-parses
            // its argument string itself, so array-based arguments alone do not stop shell
            // metacharacters from being interpreted. Strictly allowlist the value before it is
            // ever handed to cmd.exe so shell metacharacters can never reach the shell parser.
            if (!bar.matches("[a-zA-Z0-9 ._-]*")) {
                response.getWriter().println("Invalid input.");
                return;
            }
            command.add("cmd.exe");
            command.add("/c");
            command.add("echo");
        } else {
            command.add("echo");
        }
        command.add(bar);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.environment().clear();
        pb.environment().put("Foo", "bar");
        pb.directory(new java.io.File(System.getProperty("user.dir")));

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
