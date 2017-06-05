package com.sap.startupfocus.demo;

import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Date;

import org.apache.commons.lang.time.DateUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class JWTDatabaseConnector {
	private static String dbUrl = "jdbc:sap://hana2.sfphcp.com:30015/"; // UPDATE

	public static void main(String[] args) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	Class.forName("com.sap.db.jdbc.Driver");
		
		KeyPair kp = getKeysFromFile("mykey.pem");
		RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();
		Algorithm algorithmRS = Algorithm.RSA256(publicKey, privateKey);
		
		Date now = new Date();

		String token = JWT.create()
				.withSubject("sunil.wadhwa01@sap.com")
				.withIssuer("http://startupfocus.sap.com/demo/jwt")
				.withClaim("user_name", "sunil.wadhwa01@sap.com")
				.withNotBefore(DateUtils.addYears(now, -1))
				.withExpiresAt(DateUtils.addYears(now, 1))
		        .sign(algorithmRS);

		System.out.println("Connecting with token " + token);
		Connection c = DriverManager.getConnection(dbUrl, "", token);
		System.out.println("Connected to " + dbUrl);

		/* Get current user query */
        Statement stmt = c.createStatement();
        ResultSet rs = stmt.executeQuery("select CURRENT_USER from DUMMY");
        if (rs.next()) {
            String currentUser = rs.getString(1);
            System.out.println("Current User = " + currentUser);
        }
	}
	
	private static KeyPair getKeysFromFile(String filename) throws Exception {
        PEMParser parser = new PEMParser(new FileReader(filename));
        Object o = parser.readObject();
        if (!(o instanceof PEMKeyPair)) {
            throw new IOException("No key pair found in file '" + filename + "'");
        }
		JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
		KeyPair kp = converter.getKeyPair((PEMKeyPair) o);
		return kp;
	}

}
