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

@WebServlet(value = "/sqli-05/BenchmarkTest02528")
public class BenchmarkTest02528 extends HttpServlet {

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

        String[] values = request.getParameterValues("BenchmarkTest02528");
        String param;
        if (values != null && values.length > 0) param = values[0];
        else param = "";

        String bar = doSomething(request, param);

        // Only allow calls to known stored procedures with quoted string-literal
        // arguments; anything outside this allowlisted shape is rejected below
        // instead of being concatenated into the SQL call.
        java.util.regex.Matcher callMatcher =
                java.util.regex.Pattern.compile(
                                "^(verifyUserPassword|verifyEmployeeSalary)\\(((?:'[^']*'\\s*,\\s*)*'[^']*')?\\)$")
                        .matcher(bar);

        if (!callMatcher.matches()) {
            response.getWriter().println("Error processing request.");
            return;
        }

        String procedureName = callMatcher.group(1);
        java.util.List<String> callArgs = new java.util.ArrayList<String>();
        java.util.regex.Matcher argMatcher =
                java.util.regex.Pattern.compile("'([^']*)'")
                        .matcher(callMatcher.group(2) == null ? "" : callMatcher.group(2));
        while (argMatcher.find()) {
            callArgs.add(argMatcher.group(1));
        }

        StringBuilder placeholders = new StringBuilder();
        for (int i = 0; i < callArgs.size(); i++) {
            if (i > 0) placeholders.append(", ");
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
    } // end doPost

    private static String doSomething(HttpServletRequest request, String param)
            throws ServletException, IOException {

        String bar = "";
        if (param != null) {
            java.util.List<String> valuesList = new java.util.ArrayList<String>();
            valuesList.add("safe");
            valuesList.add(param);
            valuesList.add("moresafe");

            valuesList.remove(0); // remove the 1st safe value

            bar = valuesList.get(0); // get the param value
        }

        return bar;
    }
}
