package dio.dio_spring_security_jwt.security;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "security.config") // instrui o spring a procurar no arquivo de properties todas as chaves que tem esse prefixo
public class SecurityConfig {

    public static String PREFIX;
    public static String KEY;
    public static Long EXPIRATION = 3600000L;

    public void setPREFIX(String prefix){
        PREFIX = prefix;
    }

    public void setKEY(String key){
        KEY = key;
    }

    public void setEXPIRATION(Long expiration){
        EXPIRATION = expiration;
    }
}
