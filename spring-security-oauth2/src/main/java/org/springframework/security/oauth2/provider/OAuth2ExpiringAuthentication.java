package org.springframework.security.oauth2.provider;

import java.util.Date;

public class OAuth2ExpiringAuthentication extends OAuth2Authentication {
	private final Date expires;

	/**
	 * Construct an OAuth 2 authentication. Since some grant types don't require user authentication, the user
	 * authentication may be null.
	 *
	 * @param authentication
	 *            The authentication
	 * @param expires
	 *            Expiration of the pre authentication
	 */
	public OAuth2ExpiringAuthentication(OAuth2Authentication authentication, Date expires) {
		super(authentication.getOAuth2Request(), authentication.getUserAuthentication());
		this.expires = expires;
	}

	public Date getExpires() {
		return expires;
	}
}
