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

@WebServlet(value = "/sqli-00/BenchmarkTest00328")
public class BenchmarkTest00328 extends HttpServlet {

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
        java.util.Enumeration<String> headers = request.getHeaders("BenchmarkTest00328");

        if (headers != null && headers.hasMoreElements()) {
            param = headers.nextElement(); // just grab first element
        }

        // URL Decode the header value since req.getHeaders() doesn't. Unlike req.getParameters().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        String bar;

        // Simple ? condition that assigns param to bar on false condition
        int num = 106;

        bar = (7 * 42) - num > 200 ? "This should never happen" : param;

        // Only a fixed set of stored procedures may be invoked, and their arguments are bound as
        // parameters rather than concatenated into the SQL text, to prevent SQL injection.
        String procedureName = null;
        java.util.List<String> arguments = new java.util.ArrayList<String>();

        java.util.regex.Matcher matcher =
                java.util.regex.Pattern.compile("^([A-Za-z][A-Za-z0-9_]*)\\((.*)\\)$").matcher(bar);
        if (matcher.matches()) {
            String requestedName = matcher.group(1);
            String rawArgs = matcher.group(2).trim();
            if (!rawArgs.isEmpty()) {
                for (String rawArg : rawArgs.split(",")) {
                    String trimmed = rawArg.trim();
                    if (trimmed.length() >= 2 && trimmed.startsWith("'") && trimmed.endsWith("'")) {
                        trimmed = trimmed.substring(1, trimmed.length() - 1);
                    }
                    arguments.add(trimmed);
                }
            }
            if ("verifyUserPassword".equals(requestedName) && arguments.size() == 2) {
                procedureName = "verifyUserPassword";
            } else if ("verifyEmployeeSalary".equals(requestedName) && arguments.size() == 1) {
                procedureName = "verifyEmployeeSalary";
            }
        }

        try {
            if (procedureName == null) {
                response.getWriter().println("Error processing request.");
                return;
            }

            StringBuilder placeholders = new StringBuilder();
            for (int i = 0; i < arguments.size(); i++) {
                if (i > 0) placeholders.append(",");
                placeholders.append("?");
            }
            String sql = "{call " + procedureName + "(" + placeholders + ")}";

            java.sql.Connection connection =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
            java.sql.CallableStatement statement = connection.prepareCall(sql);
            for (int i = 0; i < arguments.size(); i++) {
                statement.setString(i + 1, arguments.get(i));
            }
            java.sql.ResultSet rs = statement.executeQuery();
            org.owasp.benchmark.helpers.DatabaseHelper.printResults(rs, sql, response);

        } catch (java.sql.SQLException e) {
            if (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {
                response.getWriter().println("Error processing request.");
                return;
            } else throw new ServletException(e);
        }
    }
}
