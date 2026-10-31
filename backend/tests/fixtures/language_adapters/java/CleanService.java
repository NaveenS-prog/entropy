// TEST DATA FIXTURE - CLEAN JAVA PATTERNS
package com.example.service;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class CleanService {

    public void queryUserSafe(Connection conn, String userId) throws Exception {
        // Safe parameterized query
        String query = "SELECT * FROM users WHERE id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, userId);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    System.out.println(rs.getString("username"));
                }
            }
        }
    }
}
