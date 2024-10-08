package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

import java.util.Collections;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 * 
 */
public class DefaultTokenServicesWithJwtTests extends AbstractDefaultTokenServicesTests {

	private JwtTokenStore tokenStore;
	JwtAccessTokenConverter enhancer = new JwtAccessTokenConverter();

	@Override
	protected TokenStore createTokenStore() {
		tokenStore = new JwtTokenStore(enhancer);
		return tokenStore;
	}

	@Override
	protected void configureTokenServices(DefaultTokenServices services) throws Exception {
		enhancer.afterPropertiesSet();
		services.setTokenEnhancer(enhancer);
		super.configureTokenServices(services);
	}

	@Test
	public void testRefreshedTokenHasIdThatMatchesAccessToken() throws Exception {
		JsonParser parser = JsonParserFactory.create();
		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken initialToken = getTokenServices().createAccessToken(
				authentication);
		ExpiringOAuth2RefreshToken expectedExpiringRefreshToken = (ExpiringOAuth2RefreshToken) initialToken
				.getRefreshToken();
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap(
				"client_id", "id"), "id", null, null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				expectedExpiringRefreshToken.getValue(), tokenRequest);
		Map<String, ?> accessTokenInfo = parser.parseMap(JwtHelper.decode(
				refreshedAccessToken.getValue()).getClaims());
		Map<String, ?> refreshTokenInfo = parser.parseMap(JwtHelper.decode(
				refreshedAccessToken.getRefreshToken().getValue()).getClaims());
		assertEquals("Access token ID does not match refresh token ATI",
				accessTokenInfo.get(AccessTokenConverter.JTI),
				refreshTokenInfo.get(AccessTokenConverter.ATI));
		assertNotSame("Refresh token re-used", expectedExpiringRefreshToken.getValue(),
				refreshedAccessToken.getRefreshToken().getValue());
	}

	@Test
	public void testDoubleRefresh() throws Exception {
		JsonParser parser = JsonParserFactory.create();
		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken initialToken = getTokenServices().createAccessToken(
				authentication);
		TokenRequest tokenRequest = new TokenRequest(Collections.singletonMap(
				"client_id", "id"), "id", null, null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				initialToken.getRefreshToken().getValue(), tokenRequest);
		refreshedAccessToken = getTokenServices().refreshAccessToken(
				refreshedAccessToken.getRefreshToken().getValue(), tokenRequest);
		Map<String, ?> accessTokenInfo = parser.parseMap(JwtHelper.decode(
				refreshedAccessToken.getValue()).getClaims());
		Map<String, ?> refreshTokenInfo = parser.parseMap(JwtHelper.decode(
				refreshedAccessToken.getRefreshToken().getValue()).getClaims());
		assertEquals("Access token ID does not match refresh token ATI",
				accessTokenInfo.get(AccessTokenConverter.JTI),
				refreshTokenInfo.get(AccessTokenConverter.ATI));
	}

	// gh-1109
	@Test
	public void testReuseRefreshToken() {
		getTokenServices().setReuseRefreshToken(true);

		OAuth2Authentication authentication = createAuthentication();
		OAuth2AccessToken accessToken = getTokenServices().createAccessToken(authentication);
		ExpiringOAuth2RefreshToken refreshToken = (ExpiringOAuth2RefreshToken) accessToken.getRefreshToken();

		TokenRequest tokenRequest = new TokenRequest(
				Collections.singletonMap("client_id", "id"), "id", null, null, null);
		OAuth2AccessToken refreshedAccessToken = getTokenServices().refreshAccessToken(
				refreshToken.getValue(), tokenRequest);

		JsonParser parser = JsonParserFactory.create();
		Map<String, ?> accessTokenClaims = parser.parseMap(
				JwtHelper.decode(refreshedAccessToken.getValue()).getClaims());
		Map<String, ?> refreshTokenClaims = parser.parseMap(
				JwtHelper.decode(refreshedAccessToken.getRefreshToken().getValue()).getClaims());

		assertEquals("Access token ID (JTI) does not match refresh token ATI",
				accessTokenClaims.get(AccessTokenConverter.JTI),
				refreshTokenClaims.get(AccessTokenConverter.ATI));

		Map<String, ?> previousRefreshTokenClaims = parser.parseMap(
				JwtHelper.decode(refreshToken.getValue()).getClaims());

		// The ATI claim in the refresh token is a reference to the JTI claim in the access token.
		// So when an access token is refreshed, the ATI claim in the refresh token needs to be updated
		// to the JTI claim in the refreshed access token.
		// Therefore, if DefaultTokenServices.reuseRefreshToken == true,
		// then all claims in the previous and current refresh token
		// should be equal minus the ATI claim
		previousRefreshTokenClaims.remove(AccessTokenConverter.ATI);
		refreshTokenClaims.remove(AccessTokenConverter.ATI);
		assertEquals("Refresh token not re-used", previousRefreshTokenClaims, refreshTokenClaims);
	}
}
