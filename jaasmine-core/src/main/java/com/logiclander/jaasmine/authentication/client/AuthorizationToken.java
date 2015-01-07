package com.logiclander.jaasmine.authentication.client;

/**
 * Generates SPNego tokens.
 * 
 * @author agherna
 *
 */
public interface AuthorizationToken {

	/**
	 * 
	 * @return SPNego token.
	 */
	public String generate();
	
}
