package com.logiclander.jaasmine.authentication.client;

import javax.security.auth.Subject;

import com.logiclander.jaasmine.AuthenticationType;
import com.logiclander.jaasmine.SPNegoClient;
import com.logiclander.jaasmine.authentication.AuthenticationService;
import com.logiclander.jaasmine.authentication.KeyTabAuthenticationService;

public class KeyTabAuthorizationToken implements AuthorizationToken {

	private final String servicePrincipalName;

	private final AuthenticationService authnService;

	public KeyTabAuthorizationToken(String servicePrincipalName) {
		this.servicePrincipalName = servicePrincipalName;
		authnService = new KeyTabAuthenticationService();
	}

	public KeyTabAuthorizationToken(String servicePrincipalName,
			String applicationName) {
		this.servicePrincipalName = servicePrincipalName;
		authnService = new KeyTabAuthenticationService(applicationName);
	}

	@Override
	public String generate() {
		String token = null;

		// XXX: we EXPECT keytabs to be used here, so username and password are
		// null.
		Subject loginCredential = authnService.login(null, null);
		try {
			SPNegoClient spnegoClient = new SPNegoClient(loginCredential,
					AuthenticationType.KRB5);
			token = new StringBuilder("Negotiate ").append(
					spnegoClient.generateSPNegoToken(servicePrincipalName))
					.toString();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		return token;
	}

}
