package dev.chux.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Implementation of all necessary OIDC endpoints.
 *
 */
@RestController
public class OidcController {

    private static final Logger log = LoggerFactory.getLogger(OidcController.class);

    public static final String METADATA_ENDPOINT = "/.well-known/openid-configuration";
    public static final String AUTHORIZATION_ENDPOINT = "/authorize";
    public static final String TOKEN_ENDPOINT = "/token";
    public static final String USERINFO_ENDPOINT = "/userinfo";
    public static final String JWKS_ENDPOINT = "/jwks";
    public static final String INTROSPECTION_ENDPOINT = "/introspect";

    public static final int RESPONSE_MODE_DEFAULT = 0;
    public static final int RESPONSE_MODE_JSON = 1;

    private JWSSigner signer;
    private JWKSet publicJWKSet;
    private JWSHeader jwsHeader;

    private final Map<String, AccessTokenInfo> accessTokens = new HashMap<>();
    private final Map<String, CodeInfo> authorizationCodes = new HashMap<>();
    private final SecureRandom random = new SecureRandom();

    private final OidcServerProperties serverProperties;

    public OidcController(@Autowired OidcServerProperties serverProperties) {
        this.serverProperties = serverProperties;
    }

    @PostConstruct
    public void init() throws IOException, ParseException, JOSEException {
        log.info("initializing JWK");
        JWKSet jwkSet = JWKSet.load(getClass().getResourceAsStream("/jwks.json"));
        JWK key = jwkSet.getKeys().get(0);
        signer = new RSASSASigner((RSAKey) key);
        publicJWKSet = jwkSet.toPublicJWKSet();
        jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build();
        log.info("config {}", serverProperties);
    }

    /**
     * Provides OIDC metadata. See the spec at https://openid.net/specs/openid-connect-discovery-1_0.html
     */
    @RequestMapping(value = METADATA_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<?> metadata(UriComponentsBuilder uriBuilder, HttpServletRequest req) {
        log.info("called {}", METADATA_ENDPOINT);
        String urlPrefix = serverProperties.getIssuer(); // uriBuilder.replacePath(null).build().encode().toUriString();
        Map<String, Object> m = new LinkedHashMap<>();
        // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
        // https://tools.ietf.org/html/rfc8414#section-2
        m.put("issuer", urlPrefix + "/"); // REQUIRED
        m.put("authorization_endpoint", urlPrefix + AUTHORIZATION_ENDPOINT); // REQUIRED
        m.put("token_endpoint", urlPrefix + TOKEN_ENDPOINT); // REQUIRED unless only the Implicit Flow is used
        m.put("userinfo_endpoint", urlPrefix + USERINFO_ENDPOINT); // RECOMMENDED
        m.put("jwks_uri", urlPrefix + JWKS_ENDPOINT); // REQUIRED
        m.put("introspection_endpoint", urlPrefix + INTROSPECTION_ENDPOINT);
        m.put("scopes_supported", Arrays.asList("openid", "profile", "email")); // RECOMMENDED
        m.put("response_types_supported", Arrays.asList("id_token token", "code")); // REQUIRED
        m.put("grant_types_supported", Arrays.asList("authorization_code", "implicit")); //OPTIONAL
        m.put("subject_types_supported", Collections.singletonList("public")); // REQUIRED
        m.put("id_token_signing_alg_values_supported", Arrays.asList("RS256")); // REQUIRED
        //m.put("id_token_signing_alg_values_supported", Arrays.asList("RS256", "none")); // REQUIRED
        m.put("claims_supported", Arrays.asList("sub", "iss", "name", "family_name", "given_name", "preferred_username", "email"));
        m.put("code_challenge_methods_supported", Arrays.asList("RS256")); // PKCE support advertised
        //m.put("code_challenge_methods_supported", Arrays.asList("plain", "S256")); // PKCE support advertised
        return ResponseEntity.ok().body(m);
    }

    /**
     * Provides JSON Web Key Set containing the public part of the key used to sign ID tokens.
     */
    @RequestMapping(value = JWKS_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<String> jwks(HttpServletRequest req) {
        log.info("called {}", JWKS_ENDPOINT);
        //final String jwks = publicJWKSet.toString();
        //final String jwks = publicJWKSet.toString().replaceAll("_on7PV8_", "");
        final String jwks = "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"use\":\"sig\",\"kid\":\"rsa1\",\"n\":\"x6QYjcJVU6nHw75plFWckVJ9PcBtguUBnV5fWaf6XVKnlpoXDMc6k-E-Wvtq7GtxuqdT-bdlc-yqKq-nthmVBFQxb4odQmhBW03yAvziMLetZ6jZ-HCp1tTJ7X7luxPuqZ2ql812gnF_ngLLe_YyG1WdVevZIWnM8Tx0AFBKGRM\",\"e\":\"AQAB\"}]}";
        return ResponseEntity.ok().body(jwks);
    }

    /**
     * Provides claims about a user. Requires a valid access token.
     */
    @RequestMapping(value = USERINFO_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin(allowedHeaders = {"Authorization", "Content-Type"})
    public ResponseEntity<?> userinfo(@RequestHeader("Authorization") String auth,
                                      @RequestParam(required = false) String access_token,
                                      @RequestParam(required = false) String client_id,
                                      HttpServletRequest req) {
        log.info("called " + USERINFO_ENDPOINT + " auth={} client_id={} access_token={}", auth, client_id, access_token);
        if (!auth.startsWith("Bearer ")) {
            if (access_token == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No token");
            }
            auth = access_token;
        } else {
            auth = auth.substring(7);
        }
        AccessTokenInfo accessTokenInfo = accessTokens.get(auth);
        if (accessTokenInfo == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("access token not found");
        }
        Set<String> scopes = setFromSpaceSeparatedString(accessTokenInfo.scope);
        Map<String, Object> m = new LinkedHashMap<>();
        User user = accessTokenInfo.user;
        m.put("sub", user.getSub());
        if (scopes.contains("profile")) {
            m.put("name", user.getName());
            m.put("family_name", user.getFamily_name());
            m.put("given_name", user.getGiven_name());
            m.put("preferred_username", user.getPreferred_username());
        }
        if (scopes.contains("email")) {
            m.put("email", user.getEmail());
            m.put("email_verified", Boolean.TRUE);
        }
        log.info("user={}", m);
        return ResponseEntity.ok().body(m);
    }

    /**
     * Provides information about a supplied access token.
     */
    @RequestMapping(value = INTROSPECTION_ENDPOINT, method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> introspection(@RequestParam String token,
                                           @RequestHeader("Authorization") String auth,
                                           @RequestParam(required = false) String client_id,
                                           HttpServletRequest req) {
        StringBuilder requestURL = new StringBuilder(req.getRequestURL().toString());
        String queryString = req.getQueryString();
        String URL;
        if(queryString == null) {
            URL = requestURL.toString();
        } else {
            URL = requestURL.append('?').append(queryString).toString();
        }
        log.info("called " + INTROSPECTION_ENDPOINT + " auth={} client_id={} token={} URL={}", auth, client_id, token, URL);
        final ClientInfo clientInfo = clientAuth(auth);
        log.info("client_info={}", clientInfo);
        Map<String, Object> m = new LinkedHashMap<>();
        AccessTokenInfo accessTokenInfo = accessTokens.get(token);
        if (accessTokenInfo == null) {
            log.error("token not found in memory: {}", token);
            m.put("active", false);
        } else {
            log.info("found token for user {}, releasing scopes: {}", accessTokenInfo.user.getSub(), accessTokenInfo.scope);
            // see https://tools.ietf.org/html/rfc7662#section-2.2 for all claims
            m.put("active", true);
            m.put("scope", accessTokenInfo.scope);
            m.put("client_id", accessTokenInfo.clientId);
            m.put("username", accessTokenInfo.user.getSub());
            m.put("token_type", "Bearer");
            m.put("exp", accessTokenInfo.expiration.toInstant().toEpochMilli());
            m.put("sub", accessTokenInfo.user.getSub());
            m.put("iss", accessTokenInfo.iss);
        }
        return ResponseEntity.ok().body(m);
    }

    /**
     * Provides token endpoint.
     */
    @RequestMapping(value = TOKEN_ENDPOINT, method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<?> token(@RequestParam String grant_type,
                                   @RequestParam String code,
                                   @RequestParam String redirect_uri,
                                   @RequestParam(required = false) String client_id,
                                   @RequestParam(required = false) String client_secret,
                                   @RequestParam(required = false) String code_verifier,
                                   @RequestHeader(name = "Authorization", required = false) String auth,
                                   UriComponentsBuilder uriBuilder,
                                   HttpServletRequest req) throws NoSuchAlgorithmException, JOSEException {
        StringBuilder requestURL = new StringBuilder(req.getRequestURL().toString());
        String queryString = req.getQueryString();
        String URL;
        if(queryString == null) {
            URL = requestURL.toString();
        } else {
            URL = requestURL.append('?').append(queryString).toString();
        }
        log.info("called " + TOKEN_ENDPOINT + ", grant_type={} code={} redirect_uri={} URL={}", grant_type, code, redirect_uri, URL);
        final ClientInfo clientInfo = clientAuth(auth);
        log.info("enforce_client_id={} enforce_client_secret={} client_info={}", 
            serverProperties.getEnforceClientId(), serverProperties.getEnforceSecret(), clientInfo);
        if( clientInfo != null && !clientInfo.isValid() ) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(clientInfo.getCredential());
        }
        if( clientInfo != null && clientInfo.isValid() ) {
            client_id = clientInfo.getClientId();
            client_secret = clientInfo.getClientSecret();
        }
        if (!"authorization_code".equals(grant_type)) {
            return jsonError("unsupported_grant_type", "grant_type is not authorization_code");
        }
        CodeInfo codeInfo = authorizationCodes.get(code);
        if (codeInfo == null) {
            return jsonError("invalid_grant", "code not valid");
        }
        if (!redirect_uri.equals(codeInfo.redirect_uri)) {
            return jsonError("invalid_request", "redirect_uri not valid");
        }
        if (codeInfo.codeChallenge != null) {
            // check PKCE
            if (code_verifier == null) {
                return jsonError("invalid_request", "code_verifier missing");
            }
            if ("S256".equals(codeInfo.codeChallengeMethod)) {
                MessageDigest s256 = MessageDigest.getInstance("SHA-256");
                s256.reset();
                s256.update(code_verifier.getBytes(StandardCharsets.UTF_8));
                String hashedVerifier = Base64URL.encode(s256.digest()).toString();
                if (!codeInfo.codeChallenge.equals(hashedVerifier)) {
                    log.warn("code_verifier {} hashed using S256 to {} does not match code_challenge {}", code_verifier, hashedVerifier, codeInfo.codeChallenge);
                    return jsonError("invalid_request", "code_verifier not correct");
                }
                log.info("code_verifier OK");
            } else {
                if (!codeInfo.codeChallenge.equals(code_verifier)) {
                    log.warn("code_verifier {} does not match code_challenge {}", code_verifier, codeInfo.codeChallenge);
                    return jsonError("invalid_request", "code_verifier not correct");
                }
            }
        }
        // return access token
        Map<String, String> map = new LinkedHashMap<>();
        final String audience = ( client_id != null )? client_id : codeInfo.client_id;
        String accessToken = createAccessToken(codeInfo.iss, codeInfo.user, audience, codeInfo.scope);
        map.put("access_token", accessToken);
        map.put("token_type", "Bearer");
        map.put("expires_in", String.valueOf(serverProperties.getTokenExpirationSeconds()));
        map.put("scope", codeInfo.scope);
        map.put("id_token", createIdToken(codeInfo.iss, codeInfo.user, audience, codeInfo.nonce, accessToken));
        log.info("token={}", map);
        return ResponseEntity.ok(map);
    }


    /**
     * Provides authorization endpoint.
     */
    @RequestMapping(value = AUTHORIZATION_ENDPOINT, method = RequestMethod.GET)
    public ResponseEntity<?> authorize(@RequestParam String client_id,
                                       @RequestParam(required = false) String redirect_uri,
                                       @RequestParam String response_type,
                                       @RequestParam String scope,
                                       @RequestParam(required = false) String state,
                                       @RequestParam(required = false) String nonce,
                                       @RequestParam(required = false) String client_secret,
                                       @RequestParam(required = false) String code_challenge,
                                       @RequestParam(required = false) String code_challenge_method,
                                       @RequestParam(required = false) String response_mode,
                                       @RequestHeader(name = "Authorization", required = false) String auth,
                                       UriComponentsBuilder uriBuilder,
                                       HttpServletRequest req) throws JOSEException, NoSuchAlgorithmException {
        StringBuilder requestURL = new StringBuilder(req.getRequestURL().toString());
        String queryString = req.getQueryString();
        String URL;
        if(queryString == null) {
            URL = requestURL.toString();
        } else {
            URL = requestURL.append('?').append(queryString).toString();
        }
        log.info("called " + AUTHORIZATION_ENDPOINT + " scope={} response_type={} client_id={} redirect_uri={} response_type={} response_mode={} URL={}", scope, response_type, client_id, redirect_uri, response_type, response_mode, URL);
        final int responseMode = getResponseMode(response_mode);
        if( ((redirect_uri == null) || redirect_uri.isEmpty()) && (responseMode == RESPONSE_MODE_DEFAULT) ) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("redirect_uri");
        }
        log.info("redirect enforced={} allowed_uris={}", serverProperties.getEnforceRedirect(), serverProperties.getRedirects());
        if (auth == null) {
            log.info("user and password not provided");
            return response401(client_id);
        } 
        else if( serverProperties.getEnforceRedirect() 
            && !serverProperties.getRedirects().contains(redirect_uri) ) {
            log.info("403 redirect_uri={} ", redirect_uri);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(redirect_uri);
        } else {
            String[] creds = new String(Base64.getDecoder().decode(auth.split(" ")[1])).split(":", 2);
            String login = creds[0];
            String password = creds[1];
            log.info("login={} password={} domain={} enforce_domain={} allow_all{}", login, password, 
                    serverProperties.getDomain(), serverProperties.getEnforceDomain(), serverProperties.getAllowAll());
            User user = serverProperties.getUser(login); 
            user = ( user == null )? serverProperties.getUserByEmail(login) : user;
            if( user == null && serverProperties.getAllowAll() ) {
                user = User.newUser(login, password, serverProperties.getDomain());
                if( serverProperties.getAddAll() ) {
                    serverProperties.addUser(user);
                }
                log.info("new user={}", user);
                return authorizeResponse(uriBuilder, user, response_type, client_id, scope, 
                        state, nonce, redirect_uri, code_challenge, code_challenge_method, responseMode);
            }
            if( serverProperties.getEnforceDomain() 
                    && !login.endsWith("@" + serverProperties.getDomain()) ) {
                log.info("invalid domain={} expected={}", login, serverProperties.getDomain());
                return response401(client_id);
            }
            if ( user.getPassword().equals(password) ) {
                log.info("password for user {} is correct", login);
                return authorizeResponse(uriBuilder, user, response_type, client_id, scope,
                        state, nonce, redirect_uri, code_challenge, code_challenge_method, responseMode);
            }
            log.info("wrong user and password combination");
            return response401(client_id);
        }
    }

    private ResponseEntity<?> authorizeResponse(UriComponentsBuilder uriBuilder,
                                                User user, String response_type, 
                                                String client_id, String scope,
                                                String state, String nonce, 
                                                String redirect_uri, String code_challenge, 
                                                String code_challenge_method, int responseMode) 
            throws JOSEException, NoSuchAlgorithmException {
        Set<String> responseType = setFromSpaceSeparatedString(response_type);
        String iss = uriBuilder.replacePath("/").build().encode().toUriString();
        String locationURL;
        if (responseType.contains("token") 
            || responseType.contains("id_token")
            || responseType.contains("idToken")) {
            // implicit flow
            String access_token = createAccessToken(iss, user, client_id, scope);
            String id_token = createIdToken(iss, user, client_id, nonce, access_token);
            // create tokens but do not redirect, just deliver them as JSON
            if( responseMode == RESPONSE_MODE_JSON ) {
                final Map<String, Object> tokens = new HashMap<>(2);
                tokens.put("client_id", client_id);
                tokens.put("access_token", access_token);
                tokens.put("id_token", id_token);
                tokens.put("user", user);
                return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(tokens);
            }
            locationURL = redirect_uri + "#" +
                "access_token=" + urlencode(access_token) +
                "&token_type=Bearer" +
                "&state=" + urlencode(state) +
                "&expires_in=" + serverProperties.getTokenExpirationSeconds() +
                "&id_token=" + urlencode(id_token);
            log.info("using implicit flow | user={} access_token={} id_token={} nonce={}", user, access_token, id_token, nonce);
        } else if (responseType.contains("code") 
                || responseType.contains("code_flow") ) {
            // authorization code flow
            String code = createAuthorizationCode(code_challenge, code_challenge_method, client_id, redirect_uri, user, iss, scope, nonce);
            log.info("using authorization code flow {} | user={} code_challenge={} code_challenge_method={} nonce={}", 
                    code_challenge != null ? "with PKCE" : "", user, code_challenge, code_challenge_method, nonce);
            locationURL = redirect_uri + "?" +
                "code=" + code +
                "&state=" + urlencode(state);
        } else {
            locationURL = redirect_uri + "#" + "error=unsupported_response_type";
        }
        log.info("redirect URL: {}", locationURL);
        return ResponseEntity.status(HttpStatus.FOUND).header("Location", locationURL).build();
    }

    private int getResponseMode(final String response_mode) {
        if( (response_mode == null) || response_mode.isEmpty() ) {
            return RESPONSE_MODE_DEFAULT;
        }
        switch(response_mode) {
            case "JSON":
            case "json":
                return RESPONSE_MODE_JSON;
            default: /* no-go */
        }
        return RESPONSE_MODE_DEFAULT;
    }

    private String createAuthorizationCode(String code_challenge, String code_challenge_method, String client_id, String redirect_uri, User user, String iss, String scope, String nonce) {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        String code = Base64URL.encode(bytes).toString();
        log.info("issuing code={}", code);
        authorizationCodes.put(code, new CodeInfo(code_challenge, code_challenge_method, code, client_id, redirect_uri, user, iss, scope, nonce));
        return code;
    }

    private String createAccessToken(String iss, User user, String client_id, String scope) throws JOSEException {
        // create JWT claims
        Date expiration = new Date(System.currentTimeMillis() + serverProperties.getTokenExpirationSeconds() * 1000L);
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getSub())
                .issuer(serverProperties.getIssuer() + "/")
                .audience(client_id)
                .issueTime(new Date())
                .expirationTime(expiration)
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", scope)
                .claim("name", user.getName())
                .claim("email", user.getEmail())
                .claim("email_verified", Boolean.TRUE)
                .claim("family_name", user.getFamily_name())
                .claim("given_name", user.getGiven_name())
                .claim("preferred_username", user.getPreferred_username())
                .build();
        // create JWT token
        SignedJWT jwt = new SignedJWT(jwsHeader, jwtClaimsSet);
        // sign the JWT token
        jwt.sign(signer);
        String access_token = jwt.serialize();
        accessTokens.put(access_token, new AccessTokenInfo(user, access_token, expiration, scope, client_id, iss));
        return access_token;
    }

    private String createIdToken(String iss, User user, String client_id, String nonce, String accessToken) throws NoSuchAlgorithmException, JOSEException {
        // compute at_hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.reset();
        digest.update(accessToken.getBytes(StandardCharsets.UTF_8));
        byte[] hashBytes = digest.digest();
        byte[] hashBytesLeftHalf = Arrays.copyOf(hashBytes, hashBytes.length / 2);
        Base64URL encodedHash = Base64URL.encode(hashBytesLeftHalf);
        // create JWT claims
         JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getSub())
                .issuer(serverProperties.getIssuer() + "/")
                .audience(client_id)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + serverProperties.getTokenExpirationSeconds() * 1000L))
               .jwtID(UUID.randomUUID().toString())
                .claim("nonce", nonce)
                .claim("at_hash", encodedHash)
                .claim("name", user.getName())
                .claim("email", user.getEmail())
                .claim("email_verified", Boolean.TRUE)
                .claim("family_name", user.getFamily_name())
                .claim("given_name", user.getGiven_name())
                .claim("preferred_username", user.getPreferred_username())
                .build();
        // create JWT token
        SignedJWT myToken = new SignedJWT(jwsHeader, jwtClaimsSet);
        // sign the JWT token
        myToken.sign(signer);
        return myToken.serialize();
    }

    private ClientInfo clientAuth(final String auth) {
        if( auth == null ) { return null; } 
        log.info("client auth: header={}", auth);
        final String credential = auth.substring(6);
        final String[] credentials = new String(Base64.getDecoder().decode(credential), StandardCharsets.UTF_8).split(":");
        final String client_id = credentials[0];
        final String client_secret = credentials[1];
        if( (serverProperties.getEnforceClientId() && !serverProperties.getClientId().equals(client_id))
            || (serverProperties.getEnforceSecret() && !serverProperties.getSecret().equals(client_secret)) ) {
          return new ClientInfo(credential, client_id, client_secret, false);
        }
        return new ClientInfo(credential, client_id, client_secret, true);
    }

    private static String urlencode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static ResponseEntity<String> response401(String client_id) {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.TEXT_HTML);
        responseHeaders.add("WWW-Authenticate", "Basic realm=\"OIDC\" for \"" + client_id + "\"");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).headers(responseHeaders).body("<html><head><title>OIDC – " + client_id + "</title></head><body><h1>401 Unauthorized</h1>OIDC for \"" + client_id + "\"</body></html>");
    }


    private static class ClientInfo {

        final boolean valid;
        final String credential;
        final String clientId;
        final String clientSecret;

        public ClientInfo(final String credential, final String client_id, 
                final String client_secret, final boolean valid) {
            this.credential = credential;
            this.clientId = client_id;
            this.clientSecret = client_secret;
            this.valid = valid;
        }

        public String getCredential() {
            return this.credential;
        }

        public String getClientId() {
            return this.clientId;
        }

        public String getClientSecret() {
            return this.clientSecret;
        }

        public boolean isValid() {
            return this.valid;
        }

        public String toString() {
          return "ClientInfo{" +
            "credential=" + this.credential +
            ", client_id=" + this.clientId +
            ", client_secret=" + this.clientSecret +
            ", is_valid=" + this.valid +
          '}';
        }

    }

    private static class AccessTokenInfo {
        final User user;
        final String accessToken;
        final Date expiration;
        final String scope;
        final String clientId;
        final String iss;

        public AccessTokenInfo(User user, String accessToken, Date expiration, String scope, String clientId, String iss) {
            this.user = user;
            this.accessToken = accessToken;
            this.expiration = expiration;
            this.scope = scope;
            this.clientId = clientId;
            this.iss = iss;
        }

    }

    private static class CodeInfo {
        final String codeChallenge;
        final String codeChallengeMethod;
        final String code;
        final String client_id;
        final String redirect_uri;
        final User user;
        final String iss;
        final String scope;
        final String nonce;

        public CodeInfo(String codeChallenge, String codeChallengeMethod, String code, String client_id, String redirect_uri, User user, String iss, String scope, String nonce) {
            this.codeChallenge = codeChallenge;
            this.codeChallengeMethod = codeChallengeMethod;
            this.code = code;
            this.client_id = client_id;
            this.redirect_uri = redirect_uri;
            this.user = user;
            this.iss = iss;
            this.scope = scope;
            this.nonce = nonce;
        }
    }

    private static Set<String> setFromSpaceSeparatedString(String s) {
        if (s == null || s.isBlank()) return Collections.emptySet();
        return new HashSet<>(Arrays.asList(s.split(" ")));
    }

    private static ResponseEntity<?> jsonError(String error, String error_description) {
        log.warn("error={} error_description={}", error, error_description);
        Map<String, String> map = new LinkedHashMap<>();
        map.put("error", error);
        map.put("error_description", error_description);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(map);
    }

}
