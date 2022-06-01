package testcode.saml;


import org.springframework.context.annotation.Bean;
import com.onelogin.saml2.settings.Saml2Settings;

public class OneLoginUnsafeReject {

    boolean reject = false;

    @Bean
    public Saml2Settings samlReject(){
        Saml2Settings settings = new Saml2Settings();
        settings.setRejectDeprecatedAlg(false);
        return settings;
    }

    @Bean
    public Saml2Settings samlReject2(){
        Saml2Settings settings = new Saml2Settings();
        settings.setRejectDeprecatedAlg(reject);
        return settings;
    }
}
