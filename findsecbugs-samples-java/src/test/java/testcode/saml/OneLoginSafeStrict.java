package testcode.saml;

import com.onelogin.saml2.settings.Saml2Settings;
import org.springframework.context.annotation.Bean;

public class OneLoginSafeStrict {

    boolean strict = true;

    @Bean
    public Saml2Settings samlStrict(){
        Saml2Settings settings = new Saml2Settings();
        settings.setStrict(true);
        return settings;
    }

    @Bean
    public Saml2Settings samlStrictTwo(){
        Saml2Settings settings = new Saml2Settings();
        settings.setStrict(strict);
        return settings;
    }
}
