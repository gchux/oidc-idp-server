package dev.chux.idp.oidc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;

@Component
@ConfigurationProperties(prefix="oidc")
public class OidcServerProperties {

    private Map<String, User> users;
    private Map<String, User> usersByEmail;
    private long tokenExpirationSeconds;
    private String issuer;
    private String domain;
    private String clientId;
    private String secret;
    private Set<String> redirects;
    private boolean enforceClientId;
    private boolean enforceSecret;
    private boolean enforceRedirect;
    private boolean enforceDomain;
    private boolean allowAll;
    private boolean addAll;

    public Map<String, User> getUsersByEmail() {
        return usersByEmail;
    }

    public Map<String, User> getUsers() {
        return users;
    }

    public void setUsers(Map<String, User> users) {
        this.users = users;
    }

    public User getUser(String uid) {
        return users.get(uid);
    }

    public User getUserByEmail(String email) {
        return usersByEmail.get(email);
    }

    public User addUser(User user) {
        this.usersByEmail.put(user.getEmail(), user);
        return this.users.put(user.getUid(), user);
    }

    public long getTokenExpirationSeconds() {
        return tokenExpirationSeconds;
    }

    public void setTokenExpirationSeconds(long tokenExpirationSeconds) {
        this.tokenExpirationSeconds = tokenExpirationSeconds;
    }

    public String getIssuer() {
      return this.issuer;
    }

    public void setIssuer(String issuer) {
      this.issuer = issuer;
    }

    public String getDomain() {
        return this.domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getClientId() {
      return this.clientId;
    }

    public void setClientId(String clientId) {
      this.clientId = clientId;
    }

    public String getSecret() {
      return this.secret;
    }

    public void setSecret(String secret) {
      this.secret = secret;
    }

    public Set<String> getRedirects() {
      return this.redirects;
    }

    public void setRedirects(String redirects) {
      if( redirects == null || redirects.isEmpty() ) {
        this.redirects = Collections.emptySet();
        return;
      }
      this.redirects = new HashSet<>(Arrays.asList(redirects.split(",")));
    }

    public boolean getEnforceClientId() {
      return this.enforceClientId;
    }

    public void setEnforceClientId(boolean enforceClientId) {
      this.enforceClientId = enforceClientId;
    } 

    public boolean getEnforceSecret() {
      return this.enforceSecret;
    }

    public void setEnforceSecret(boolean enforceSecret) {
      this.enforceSecret = enforceSecret;
    } 

    public boolean getEnforceRedirect() {
      return this.enforceRedirect;
    }

    public void setEnforceRedirect(boolean enforceRedirect) {
      this.enforceRedirect = enforceRedirect;
    } 

    public boolean getEnforceDomain() {
      return this.enforceDomain;
    }

    public void setEnforceDomain(boolean enforceDomain) {
      this.enforceDomain = enforceDomain;
    } 

    public boolean getAllowAll() {
        return this.allowAll;
    }

    public void setAllowAll(boolean allowAll) {
        this.allowAll = allowAll;
    }

    public boolean getAddAll() {
        return this.addAll;
    }

    public void setAddAll(boolean addAll) {
        this.addAll = addAll;
    }

    @Override
    public String toString() {
        return "OidcServerProperties{" +
                "users=" + this.users +
                ", tokenExpirationSeconds=" + this.tokenExpirationSeconds +
                ", issuer=" + this.issuer +
                ", domain=" + this.domain +
                ", clientId=" + this.clientId +
                ", secret=" + this.secret +
                ", redirects=" + this.redirects +
                ", enforceClientId=" + this.enforceClientId +
                ", enforceSecret=" + this.enforceSecret +
                ", enforceRedirect=" + this.enforceRedirect +
                ", enforceDomain=" + this.enforceDomain +
                ", allowAll=" + this.allowAll +
                ", addAll=" + this.addAll +
                '}';
    }

    @PostConstruct
    public void init() {
        usersByEmail = new HashMap<>();
        for (Map.Entry<String, User> userEntry : users.entrySet()) {
            User user = userEntry.getValue();
            String login = userEntry.getKey();
            user.setUid(login);
            user.setLogname(user.getEmail());
            user.setPreferred_username(login);
            user.setName(user.getGiven_name()+" "+user.getFamily_name());
            usersByEmail.put(user.getEmail(), user);
        }
    }

}
