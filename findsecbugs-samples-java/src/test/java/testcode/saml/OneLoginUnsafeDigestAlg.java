package testcode.saml;

import org.springframework.context.annotation.Bean;
import com.onelogin.saml2.settings.Saml2Settings;

public class OneLoginUnsafeDigestAlg {

    @Bean
    public Saml2Settings samlDigest(){
        Saml2Settings settings = new Saml2Settings();
        // unsafe
        settings.setDigestAlgorithm("http://www.w3.org/2000/09/xmldsig#sha1");
        return settings;
    }

    @Bean
    public Saml2Settings samlDigest2(){
        Saml2Settings settings = new Saml2Settings();
        // safe
        settings.setDigestAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");
        return settings;
    }
}
