// TEST DATA FIXTURE - VULNERABLE JAVA PATTERNS
package com.example.service;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.Statement;

public class VulnerableService {

    public void queryUser(Connection conn, String userId) throws Exception {
        Statement stmt = conn.createStatement();
        // SQL Injection via concatenation (ENT-JAVA-001)
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        stmt.executeQuery(query);
    }

    public Object restoreSession(byte[] payload) throws Exception {
        // Unsafe deserialization (ENT-JAVA-002)
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
        return ois.readObject();
    }

    public void runMaintenance(String command) throws Exception {
        // Command injection risk (ENT-JAVA-003)
        Runtime.getRuntime().exec("sh -c " + command);
    }
}
