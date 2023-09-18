package dev.chux.oidc;

public class User {
    private String logname;
    private String password;
    private String uid;
    private String sub;
    private String name;
    private String given_name;
    private String family_name;
    private String email;
    private String preferred_username;

    public String getLogname() {
        return logname;
    }

    public void setLogname(String logname) {
        this.logname = logname;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getGiven_name() {
        return given_name;
    }

    public void setGiven_name(String given_name) {
        this.given_name = given_name;
    }

    public String getFamily_name() {
        return family_name;
    }

    public void setFamily_name(String family_name) {
        this.family_name = family_name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPreferred_username() {
        return preferred_username;
    }

    public void setPreferred_username(String preferred_username) {
        this.preferred_username = preferred_username;
    }

    public String getUid() {
        return this.uid;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    private static String setEmail(User user, String login, String domain) {
        final String atDomain = "@" + domain;
        if( login.endsWith(atDomain) 
                || login.contains(atDomain)
                || login.contains("@")) {
            user.setEmail(login);
            return login.split("@")[0];
        } 
        user.setEmail(login + atDomain);
        return login;
    }

    public static User newUser(String login, String password, String domain) {
        final User user = new User();
        login = setEmail(user, login, domain);
        user.setUid(login);
        user.setSub(login);
        user.setLogname(login);
        user.setName(login);
        user.setGiven_name(login);
        user.setFamily_name(login);
        user.setPreferred_username(login);
        user.setPassword(password);
        return user;
    }

    @Override
    public String toString() {
        return "User{" +
                "logname='" + logname + '\'' +
                ", password='" + password + '\'' +
                ", uid='" + uid + '\'' +
                ", sub='" + sub + '\'' +
                ", name='" + name + '\'' +
                ", given_name='" + given_name + '\'' +
                ", family_name='" + family_name + '\'' +
                ", email='" + email + '\'' +
                ", preferred_username='" + preferred_username + '\'' +
                '}';
    }
}
