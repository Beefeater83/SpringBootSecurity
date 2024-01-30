package ua.diakonov.FirstSecurityApp.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import ua.diakonov.FirstSecurityApp.models.Person;
import ua.diakonov.FirstSecurityApp.services.PersonDetailsService;
@Component
public class PersonValidator implements Validator {
    private final PersonDetailsService personDetailsService;
    @Autowired
    public PersonValidator(PersonDetailsService personDetailsService) {
        this.personDetailsService = personDetailsService;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return Person.class.equals(aClass);
    }

    @Override
    public void validate(Object o, Errors errors) {
    Person person = (Person) o;
    try{
    personDetailsService.loadUserByUsername(person.getUsername());
    }catch (UsernameNotFoundException ignored){
        return;// все ок пользователь не найден
    }
    errors.rejectValue("username", "", "Человек с таким именем уже существует");
    }
}
