package testcode.saml;

import java.time.Instant;
import java.util.Date;

import net.shibboleth.utilities.java.support.security.impl.RandomIdentifierGenerationStrategy;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import scala.util.Random;

import javax.xml.namespace.QName;


public class OpenSamlAuthnReq {
    private static final String IPD_SSO_DESTINATION = "https://idp.example.com/singleSingOnService";
    private static final String SP_ASSERTION_CONSUMER_SERVICE_URL = "https://sp.example.com/assertionConsumerService";
    private static final String SP_ISSUED_ID = "IssuerEntityId";
    private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

    static {
        secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

    }


    public static AuthnRequest buildAuthnRequest() {
        AuthnRequest authnRequest = buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(DateTime.now());
        authnRequest.setDestination(IPD_SSO_DESTINATION);
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(SP_ASSERTION_CONSUMER_SERVICE_URL);


        // this is "Where ID is a string uniquely identifying the request"
        // authnRequest.setID(generateSecureRandomId());

        // this is "SP identifies the Service Provider that initiated the request"
        authnRequest.setIssuer(buildIssuer());


        authnRequest.setNameIDPolicy(buildNameIdPolicy());

        return authnRequest;
    }

    // cfg, classes and methods, look into multiple methods and classes dataflow
    // start with methods, then classes

    public static AuthnRequest buildAuthnRequestNoID() {
        AuthnRequest authnRequest = buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(DateTime.now());
        authnRequest.setDestination(IPD_SSO_DESTINATION);
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(SP_ASSERTION_CONSUMER_SERVICE_URL);


        // this is "Where ID is a string uniquely identifying the request"
        // authnRequest.setID(generateSecureRandomId());

        // this is "SP identifies the Service Provider that initiated the request"
        authnRequest.setIssuer(buildIssuer());


        authnRequest.setNameIDPolicy(buildNameIdPolicy());

        return authnRequest;
    }

    public static AuthnRequest buildAuthnRequestNoSetIssuer() {
        AuthnRequest authnRequest = buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(DateTime.now());
        authnRequest.setDestination(IPD_SSO_DESTINATION);
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(SP_ASSERTION_CONSUMER_SERVICE_URL);


        // this is "Where ID is a string uniquely identifying the request"
        authnRequest.setID(generateSecureRandomId());

        // this is "SP identifies the Service Provider that initiated the request"
        // authnRequest.setIssuer(buildIssuer());


        authnRequest.setNameIDPolicy(buildNameIdPolicy());

        return authnRequest;
    }

    public static AuthnRequest buildAuthnRequestMissingBoth() {
        AuthnRequest authnRequest = buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(DateTime.now());
        authnRequest.setDestination(IPD_SSO_DESTINATION);
        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        authnRequest.setAssertionConsumerServiceURL(SP_ASSERTION_CONSUMER_SERVICE_URL);


        // this is "Where ID is a string uniquely identifying the request"
        // authnRequest.setID(generateSecureRandomId());

        // this is "SP identifies the Service Provider that initiated the request"
        // authnRequest.setIssuer(buildIssuer());

        authnRequest.setNameIDPolicy(buildNameIdPolicy());

        return authnRequest;
    }





    @SuppressFBWarnings
    public static NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameIDType.TRANSIENT);

        return nameIDPolicy;
    }

    @SuppressFBWarnings
    public static Issuer buildIssuer() {
        Issuer issuer = buildSAMLObject(Issuer.class);
        issuer.setValue(SP_ISSUED_ID);

        return issuer;
    }

    @SuppressFBWarnings
    public static <T> T buildSAMLObject(final Class<T> clazz) {
        T object = null;
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T)builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        } catch (NoSuchFieldException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        }

        return object;
    }

    @SuppressFBWarnings
    public static String generateSecureRandomId() {
        return secureRandomIdGenerator.generateIdentifier();
    }
}