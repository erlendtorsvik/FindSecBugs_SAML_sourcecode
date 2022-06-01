package testcode.saml;

import com.onelogin.saml2.settings.Saml2Settings;
import org.springframework.context.annotation.Bean;

public class OneLoginUnsafeXmlValidation {

    boolean wantXMLValidation = false;

    @Bean
    public Saml2Settings samlSetting(){
        Saml2Settings settings = new Saml2Settings();
        settings.setWantXMLValidation(false);
        return settings;
    }

    @Bean
    public Saml2Settings samlSettingTwo(){
        Saml2Settings settings = new Saml2Settings();
        settings.setWantXMLValidation(wantXMLValidation);
        return settings;
    }
}
