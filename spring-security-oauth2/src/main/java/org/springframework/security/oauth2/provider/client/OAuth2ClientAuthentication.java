package org.springframework.security.oauth2.provider.client;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 * An OAuth2 Authentication Token implementation used for OAuth 2.0 Client Authentication.
 */
public class OAuth2ClientAuthentication extends OAuth2Authentication {
	private ClientDetails clientDetails;

	/**
	 * Construct an OAuth 2 authentication. Since the client credentials grant don't require user authentication, the
	 * user authentication is null.
	 *
	 * @param storedRequest
	 *            The authorization request (must not be null).
	 * @param clientDetails
	 *            The client details
	 */
	public OAuth2ClientAuthentication(
			OAuth2Request storedRequest,
			ClientDetails clientDetails) {
		super(storedRequest, null);
		this.clientDetails = clientDetails;
	}

	public ClientDetails getClientDetails() {
		return clientDetails;
	}
}
