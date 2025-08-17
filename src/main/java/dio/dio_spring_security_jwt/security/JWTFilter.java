package dio.dio_spring_security_jwt.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
@Component
public class JWTFilter extends OncePerRequestFilter { // Verifica a integridade do token, será executado apenas uma vez por requisição para evitar trabalho desnecessário
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Obtém o token do cabeçalho da requisição, usando a "HEADER_AUTHORIZATION"
        String token = request.getHeader(JWTCreator.HEADER_AUTHORIZATION);
        // Essa implementação está validando a integridade do token usando o JWTCreator e fazendo a autenticação do usuário caso seja válida, se não, há um tratamento de exceção para isso
        try {
            if (token != null && !token.isEmpty()) {
                JWTObject tokenObject = JWTCreator.create(token, SecurityConfig.PREFIX, SecurityConfig.KEY); // usando a classe JWTCreator para validar o token
                List<SimpleGrantedAuthority> authorities = authorities(tokenObject.getRoles());
                UsernamePasswordAuthenticationToken userToken = new UsernamePasswordAuthenticationToken(tokenObject.getSubject(),
                        null, authorities); // Um objeto de autenticação do Spring Security é criado com as informações do token
                SecurityContextHolder.getContext().setAuthentication(userToken); // Injetando o objeto de autenticação no contexto de segurança do Spring. Após isso a requisição é dada como autenticada e as regras de acesso feitas no WebSecurityConfig são aplicadas
            } else {
                SecurityContextHolder.clearContext();
            }
            filterChain.doFilter(request, response); // Passa a requisição para o próximo filtro da cadeia
            // fim da validação de integridade do token
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            e.printStackTrace();
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }
    }

    private List<SimpleGrantedAuthority> authorities(List<String> roles){ // Método para converter a lista de roles vindas do token para o formato que o Spring Security espera, que é do tipo String para o SimpleGrantedAuthority
        return roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()); // Mapeia cada string de role para um novo objeto SimpleGrantedAuthority
    }
}
