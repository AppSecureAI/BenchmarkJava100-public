/**
 * OWASP Benchmark v1.2
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
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@WebServlet(value = "/sqli-00/BenchmarkTest00008")
public class BenchmarkTest00008 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    // Allowlist of stored procedures that may be invoked through this endpoint.
    private static final java.util.Set<String> ALLOWED_PROCEDURES =
            new java.util.HashSet<>(
                    java.util.Arrays.asList("verifyUserPassword", "verifyEmployeeSalary"));

    // Matches "procedureName('arg1','arg2', ...)" with only quoted string-literal arguments.
    private static final java.util.regex.Pattern CALL_PATTERN =
            java.util.regex.Pattern.compile(
                    "^([A-Za-z_][A-Za-z0-9_]*)\\(\\s*((?:'[^']*'\\s*,\\s*)*'[^']*')?\\s*\\)$");

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        // some code
        response.setContentType("text/html;charset=UTF-8");

        String param = "";
        if (request.getHeader("BenchmarkTest00008") != null) {
            param = request.getHeader("BenchmarkTest00008");
        }

        // URL Decode the header value since req.getHeader() doesn't. Unlike req.getParameter().
        param = java.net.URLDecoder.decode(param, "UTF-8");

        // Only a call to an allowlisted procedure with quoted string-literal arguments is
        // accepted; the procedure name and argument values are never concatenated into the
        // SQL text itself.
        java.util.regex.Matcher callMatcher = CALL_PATTERN.matcher(param.trim());
        if (!callMatcher.matches() || !ALLOWED_PROCEDURES.contains(callMatcher.group(1))) {
            response.getWriter().println("Error processing request.");
            return;
        }

        String procedureName = callMatcher.group(1);
        java.util.List<String> callArgs = new java.util.ArrayList<>();
        String rawArgs = callMatcher.group(2);
        if (rawArgs != null) {
            java.util.regex.Matcher argMatcher =
                    java.util.regex.Pattern.compile("'([^']*)'").matcher(rawArgs);
            while (argMatcher.find()) {
                callArgs.add(argMatcher.group(1));
            }
        }

        StringBuilder placeholders = new StringBuilder();
        for (int i = 0; i < callArgs.size(); i++) {
            if (i > 0) placeholders.append(",");
            placeholders.append("?");
        }
        String sql = "{call " + procedureName + "(" + placeholders + ")}";

        try {
            java.sql.Connection connection =
                    org.owasp.benchmark.helpers.DatabaseHelper.getSqlConnection();
            java.sql.CallableStatement statement = connection.prepareCall(sql);
            for (int i = 0; i < callArgs.size(); i++) {
                statement.setString(i + 1, callArgs.get(i));
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
