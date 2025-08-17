package dio.dio_spring_security_jwt.security;

import java.util.Arrays;
import java.util.Date;
import java.util.List;
// JWTObject é só um objeto que é usado como modelo para levar os dados para criação do token e validação
public class JWTObject { // Objeto que será convertido em token ou token que será convertido em um objeto.
    private String subject; // nome do usuário
    private Date issuedAt; // data de criação do token
    private Date expiration; // data de expiração do token
    private List<String> roles; // perfis de acesso

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public Date getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Date getExpiration() {
        return expiration;
    }

    public void setExpiration(Date expiration) {
        this.expiration = expiration;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public void setRoles(String... roles){
        this.roles = Arrays.asList(roles);
    }
}
