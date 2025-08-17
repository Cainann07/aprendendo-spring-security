package dio.dio_spring_security_jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // Habilita a segurança em nível de método, como @PreAuthorize.
public class WebSecurityConfig {

    // Define o BCryptPasswordEncoder como o bean padrão para criptografar senhas.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // A partir do Spring Security 6, a configuração da segurança é feita por meio
    // de um SecurityFilterChain.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JWTFilter jwtAuthFilter) throws Exception {
        // Desabilita a proteção CSRF, que é comum para APIs REST.
        http.csrf(AbstractHttpConfigurer::disable)
                // Habilita a segurança de Cors.
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(authorize -> authorize
                        // Permite acesso irrestrito a URLs do Swagger e do H2 Console.
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**", "/h2-console/**").permitAll()
                        // Permite acesso irrestrito ao endpoint de login.
                        .requestMatchers(HttpMethod.POST, "/login").permitAll()
                        // Permite acesso irrestrito ao endpoint para criar novos usuários.
                        .requestMatchers(HttpMethod.POST, "/users").permitAll()
                        // Apenas usuários com a role "USERS" ou "MANAGERS" podem acessar.
                        .requestMatchers(HttpMethod.GET, "/users").hasAnyRole("USERS", "MANAGERS")
                        // Apenas usuários com a role "MANAGERS" podem acessar.
                        .requestMatchers(HttpMethod.GET, "/managers").hasAnyRole("MANAGERS")
                        // Exige autenticação para todas as outras requisições não especificadas.
                        .anyRequest().authenticated()
                )
                // Adiciona o filtro JWT antes do filtro de autenticação padrão do Spring.
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                // Configura a política de criação de sessão como STATELESS, o que é ideal para JWT.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // Permite que o H2 Console seja visualizado no navegador.
        // A linha "http.headers().frameOptions().disable()" foi substituída por:
        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));

        return http.build();
    }
}
