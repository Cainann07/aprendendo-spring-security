package dio.dio_spring_security_jwt.service;

import dio.dio_spring_security_jwt.model.User;
import dio.dio_spring_security_jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {  // Gerenciador da Lógica de negócio
    @Autowired
    private UserRepository repository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public void createUser(User user){
        String pass = user.getPassword();
        // Criptografando a senha antes de salvar no banco
        user.setPassword(passwordEncoder.encode(pass));
        repository.save(user);
    }
}
