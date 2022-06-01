package testcode.saml;

import org.springframework.context.annotation.Bean;
import com.onelogin.saml2.settings.Saml2Settings;

public class OneLoginUnsafeSignAlg {

    @Bean
    public Saml2Settings samlSign(){
        Saml2Settings settings = new Saml2Settings();
        // unsafe
        settings.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        return settings;
    }

    @Bean
    public Saml2Settings samlSign2(){
        Saml2Settings settings = new Saml2Settings();
        // unsafe
        settings.setSignatureAlgorithm("http://www.w3.org/2000/09/xmldsig#dsa-sha1");
        return settings;
    }

    @Bean
    public Saml2Settings samlSign3(){
        Saml2Settings settings = new Saml2Settings();
        // safe
        settings.setSignatureAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        return settings;
    }
}
