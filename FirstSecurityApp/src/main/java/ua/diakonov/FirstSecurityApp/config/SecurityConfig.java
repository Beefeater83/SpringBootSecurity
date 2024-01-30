package ua.diakonov.FirstSecurityApp.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import ua.diakonov.FirstSecurityApp.services.PersonDetailsService;


@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final PersonDetailsService personDetailsService;
    @Autowired
    public SecurityConfig(PersonDetailsService personDetailsService) {
        this.personDetailsService = personDetailsService;
    }
    @Override //конфигурирую сам Spring Security и авторизацию
    protected void configure(HttpSecurity http)throws Exception{
        http.authorizeRequests()
             //   .antMatchers("/admin").hasRole("ADMIN") убирал чтобы дать доступ с помощью аннотации @PreAuthorize
                .antMatchers("/auth/login", "/auth/registration", "/error").permitAll() //сюда пускаю без авторизации
               // .anyRequest().authenticated() //иначе авторизация. более специфичные правила ставлю выше
                .anyRequest().hasAnyRole("USER", "ADMIN")
                .and()// соединяю разные по логике настройки
                .formLogin().loginPage("/auth/login") // вызываю свою форму
                .loginProcessingUrl("/process_login") // ответ с формы уходит на проверку
                .defaultSuccessUrl("/hello", true) //при успешной проверке вызываю форму, true -чтобы всегда перенапрвляло
                .failureUrl("/auth/login?error")
        // при неуспешной перенаправит обратно с ключем в параметрах error, который отправится на контроллер и далее форму
        // на форме отработает по ключу шаблонизатор и выведет сообщение об ошибке
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/auth/login");
    }
    //настраивает аутентификацию
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(personDetailsService)
                .passwordEncoder(getPasswordEncoder());
    }
    @Bean
    public PasswordEncoder getPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
