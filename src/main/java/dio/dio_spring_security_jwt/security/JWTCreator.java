package dio.dio_spring_security_jwt.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JWTCreator {
    public static final String HEADER_AUTHORIZATION = "Authorization"; // Define o nome do Header HTTP onde o token será enviado
    public static final String ROLES_AUTHORITIES = "authorities"; // Define o nome da "claim"(informação) dentro do JWT que conterá as roles(permissões) do usuário

    public static String create(String prefix, String key, JWTObject jwtObject){ // Pega o prefixo, a chave que vem via propriedades e um objeto que vai ser gerado por alguém com acesso ao banco de dados. Tudo isso para gerar o token
        // é o método que de fato cria o token
        String token = Jwts.builder().setSubject(jwtObject.getSubject()).setIssuedAt(jwtObject.getIssuedAt()).setExpiration(jwtObject.getExpiration())
                .claim(ROLES_AUTHORITIES, checkRoles(jwtObject.getRoles())).signWith(SignatureAlgorithm.HS512, key).compact();
        return prefix + " " + token; // Token montado com prefixo para enviar nas requsições
    }

    public static JWTObject create(String token, String prefix, String key) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException{
        // Método que valida as informações do token recebido
        SecretKey secureKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(key));

        JWTObject object = new JWTObject();
        token = token.replace(prefix, "");// remove o prefixo
        Claims claims = Jwts.parser(). // inicia o processo de análise do token
                setSigningKey(secureKey). // Define a chave secreta para ser utilizada
                parseClaimsJws(token). // Aqui é realizada a validação
                getBody();  // retorna o payload(ou corpo) do token
        object.setSubject(claims.getSubject()); // Extrai as informações do token e as coloca no objeto JWTObject(o tipo do retorno do método) para serem usadas na aplicação
        object.setExpiration(claims.getExpiration());
        object.setIssuedAt(claims.getIssuedAt());
        object.setRoles((List) claims.get(ROLES_AUTHORITIES));
        return object;
    }

    private static List<String> checkRoles(List<String> roles){ // Método para garantir que as roles tenham o prefixo "ROLE_" e não tenham esse prefixo duplicado.
        return roles.stream().map(s -> "ROLE_".concat(s.replaceAll("ROLE_", ""))).collect(Collectors.toUnmodifiableList());
    }
}
