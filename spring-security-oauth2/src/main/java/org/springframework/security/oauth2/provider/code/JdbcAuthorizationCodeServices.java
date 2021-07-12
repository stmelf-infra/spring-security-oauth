package org.springframework.security.oauth2.provider.code;

import java.nio.charset.StandardCharsets;
import java.sql.Types;
import java.util.Date;

import javax.sql.DataSource;

import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.support.SqlLobValue;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2ExpiringAuthentication;
import org.springframework.security.oauth2.provider.client.TokenEndpointAuthMethod;

import com.google.common.hash.Hashing;

/**
 * Implementation of authorization code services that stores the codes and authentication in a database.
 * 
 * @author Ken Dombeck
 * @author Dave Syer
 */
public class JdbcAuthorizationCodeServices implements AuthorizationCodeServices {
	private final ClientDetailsService clientDetailsService;
	private RandomValueStringGenerator generator = new RandomValueStringGenerator();

	private final String DEFAULT_SELECT_STATEMENT =
			"select code, authentication, expires, challenge from oauth_code where code = ?";
	private final String DEFAULT_INSERT_STATEMENT =
			"insert into oauth_code (code, authentication, challenge, expires) values (?, ?, ?, ?)";
	private final String DEFAULT_DELETE_STATEMENT = "delete from oauth_code where code = ?";

	private String selectAuthenticationSql = DEFAULT_SELECT_STATEMENT;
	private String insertAuthenticationSql = DEFAULT_INSERT_STATEMENT;
	private String deleteAuthenticationSql = DEFAULT_DELETE_STATEMENT;

	private final JdbcTemplate jdbcTemplate;

	public JdbcAuthorizationCodeServices(DataSource dataSource,
										 ClientDetailsService clientDetailsService) {
		this.jdbcTemplate = new JdbcTemplate(dataSource);
		this.clientDetailsService = clientDetailsService;
	}

	@Override
	public String createAuthorizationCode(OAuth2Authentication authentication) {
		String codeChallenge = getRequestParameter(authentication, "code_challenge");
		var client = clientDetailsService.loadClientByClientId(authentication.getOAuth2Request().getClientId());
		if (client.getTokenEndpointAuthMethod() != TokenEndpointAuthMethod.client_secret_basic) {
			// for public clients with authentication method 'none' the PKCE is required
			if (null == codeChallenge) {
				throw new InvalidRequestException("code_challenge not provided");
			}
		}

		if (null != codeChallenge) {
			String pkceChallengeMethod = getRequestParameter(authentication, "code_challenge_method");
			if (null != pkceChallengeMethod && !pkceChallengeMethod.equalsIgnoreCase("S256")) {
				// we are enforcing S256 challenge method, the plain method is not secure enough and is not supported
				throw new InvalidRequestException("code_challenge_method not supported");
			}
		}
		String code = generator.generate();
		var expiresAt = new Date(System.currentTimeMillis() + client.getAuthCodeValiditySeconds() * 1000L);

		jdbcTemplate.update(
				insertAuthenticationSql,
				new Object[] {
						Hashing.sha256().hashString(code, StandardCharsets.UTF_8).toString(),
						new SqlLobValue(SerializationUtils.serialize(authentication)),
						codeChallenge,
						expiresAt },
				new int[] {
						Types.VARCHAR,
						Types.BLOB,
						Types.VARCHAR,
						Types.TIMESTAMP });

		return code;
	}

	@Override
	public OAuth2Authentication consumeAuthorizationCode(String code) throws InvalidGrantException {
		OAuth2ExpiringAuthentication authentication;
		final String codeId = Hashing.sha256().hashString(code, StandardCharsets.UTF_8).toString();
		try {
			authentication = jdbcTemplate.queryForObject(
					selectAuthenticationSql,
					(rs, rowNum) -> new OAuth2ExpiringAuthentication(
							SerializationUtils.deserialize(rs.getBytes("authentication")),
							rs.getTimestamp("expires")),
					codeId);
		}
		catch (EmptyResultDataAccessException e) {
			throw new InvalidGrantException("Authorization code does not exist");
		}

		if (authentication != null) {
			jdbcTemplate.update(deleteAuthenticationSql, codeId);
			if (authentication.getExpires().before(new Date())) {
				throw new InvalidGrantException("Authorization code expired");
			}
		}

		return authentication;
	}

	protected String getRequestParameter(OAuth2Authentication authentication, String param) {
		return authentication.getOAuth2Request().getRequestParameters().get(param);
	}


	public void setSelectAuthenticationSql(String selectAuthenticationSql) {
		this.selectAuthenticationSql = selectAuthenticationSql;
	}

	public void setInsertAuthenticationSql(String insertAuthenticationSql) {
		this.insertAuthenticationSql = insertAuthenticationSql;
	}

	public void setDeleteAuthenticationSql(String deleteAuthenticationSql) {
		this.deleteAuthenticationSql = deleteAuthenticationSql;
	}
}
