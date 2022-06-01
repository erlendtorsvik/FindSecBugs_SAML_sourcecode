package testcode.saml;

import com.onelogin.saml2.settings.Saml2Settings;
import org.springframework.context.annotation.Bean;

public class OneLoginSafeReject {

    boolean reject = true;

    @Bean
    public Saml2Settings samlReject(){
        Saml2Settings settings = new Saml2Settings();
        settings.setRejectDeprecatedAlg(true);
        return settings;
    }

    @Bean
    public Saml2Settings samlReject2(){
        Saml2Settings settings = new Saml2Settings();
        settings.setRejectDeprecatedAlg(reject);
        return settings;
    }
}
