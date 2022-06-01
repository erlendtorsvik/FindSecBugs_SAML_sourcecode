package testcode.saml;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import net.shibboleth.utilities.java.support.security.impl.RandomIdentifierGenerationStrategy;
import org.apache.xml.security.utils.EncryptionConstants;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/* A Response must contain all these elements. Where ID is a string uniquely identifying the response.
SP identifies the recipient of the response. IdP identifies the identity provider authorizing the response.
{AA} K -1/IdP is the assertion digitally signed with the private key of the IdP
 */

public class OpenSamlResponse {
    private static final String IPD_SSO_DESTINATION = "https://idp.example.com/singleSingOnService";
    private static final String SP_ASSERTION_CONSUMER_SERVICE = "https://sp.example.com/assertionConsumerService";
    private static final String SP_ISSUED_ID = "IssuerEntityId";
    private static final String IDP_ENTITY_ID = "TestIDP";
    private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

    private static final Credential credential;

    static {
        credential = generateCredential();
    }

    // generation of public and private key
    private static Credential generateCredential() {
        try {
            KeyPair keyPair = KeySupport.generateKeyPair("RSA", 1024, null);
            return CredentialSupport.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static Credential getCredential() {
        return credential;
    }

    public Response buildResponse() {

        // Artifact response, commented out as it is not needed for the detector test

        /*ArtifactResponse artifactResponse = buildSAMLObject(ArtifactResponse.class);

        Issuer issuer = buildSAMLObject(Issuer.class);
        artifactResponse.setIssuer(issuer);
        artifactResponse.setIssueInstant(DateTime.now());
        artifactResponse.setDestination(SP_ASSERTION_CONSUMER_SERVICE);

        artifactResponse.setID(generateSecureRandomId());*/

        /*Status status = buildSAMLObject(Status.class);
        StatusCode statusCode = buildSAMLObject(StatusCode.class);
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        artifactResponse.setStatus(status);*/

        Response response = buildSAMLObject(Response.class);
        // SP identifies the recipient of the response.
        response.setDestination(SP_ASSERTION_CONSUMER_SERVICE);
        response.setIssueInstant(DateTime.now());
        // Where ID is a string uniquely identifying the response.
        response.setID(generateSecureRandomId());
        Issuer issuer2 = buildSAMLObject(Issuer.class);
        issuer2.setValue(IDP_ENTITY_ID);

        // IdP identifies the identity provider authorizing the response.
        response.setIssuer(issuer2);

        Status status2 = buildSAMLObject(Status.class);
        StatusCode statusCode2 = buildSAMLObject(StatusCode.class);
        statusCode2.setValue(StatusCode.SUCCESS);
        status2.setStatusCode(statusCode2);

        response.setStatus(status2);

        // artifactResponse.setMessage(response);

        Assertion assertion = buildAssertion();

        // Sign the assertion with private key of idp
        Signature signature = buildSAMLObject(Signature.class);
        signature.setSigningCredential(getCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        assertion.setSignature(signature);

        try {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

        // signAssertion(assertion);
        // EncryptedAssertion encryptedAssertion = encryptAssertion(assertion);

        // response.getEncryptedAssertions().add(encryptedAssertion);
        response.getAssertions().add(assertion);
        return response;
    }

    public Response buildResponseNoSP() {

        Response response = buildSAMLObject(Response.class);
        // SP identifies the recipient of the response.
        // response.setDestination(SP_ASSERTION_CONSUMER_SERVICE);
        response.setIssueInstant(DateTime.now());
        // Where ID is a string uniquely identifying the response.
        response.setID(generateSecureRandomId());
        Issuer issuer2 = buildSAMLObject(Issuer.class);
        issuer2.setValue(IDP_ENTITY_ID);

        // IdP identifies the identity provider authorizing the response.
        response.setIssuer(issuer2);

        Status status2 = buildSAMLObject(Status.class);
        StatusCode statusCode2 = buildSAMLObject(StatusCode.class);
        statusCode2.setValue(StatusCode.SUCCESS);
        status2.setStatusCode(statusCode2);

        response.setStatus(status2);

        Assertion assertion = buildAssertion();


        // Sign the assertion with private key of idp
        Signature signature = buildSAMLObject(Signature.class);
        signature.setSigningCredential(getCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        assertion.setSignature(signature);

        try {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

        // EncryptedAssertion encryptedAssertion = encryptAssertion(assertion);

        // response.getEncryptedAssertions().add(encryptedAssertion);
        response.getAssertions().add(assertion);
        return response;
    }

    public Response buildResponseNoID() {

        Response response = buildSAMLObject(Response.class);
        // SP identifies the recipient of the response.
        response.setDestination(SP_ASSERTION_CONSUMER_SERVICE);
        response.setIssueInstant(DateTime.now());
        // Where ID is a string uniquely identifying the response.
        // response.setID(generateSecureRandomId());
        Issuer issuer2 = buildSAMLObject(Issuer.class);
        issuer2.setValue(IDP_ENTITY_ID);

        // IdP identifies the identity provider authorizing the response.
        response.setIssuer(issuer2);

        Status status2 = buildSAMLObject(Status.class);
        StatusCode statusCode2 = buildSAMLObject(StatusCode.class);
        statusCode2.setValue(StatusCode.SUCCESS);
        status2.setStatusCode(statusCode2);

        response.setStatus(status2);

        Assertion assertion = buildAssertion();


        // Sign the assertion with private key of idp
        Signature signature = buildSAMLObject(Signature.class);
        signature.setSigningCredential(getCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        assertion.setSignature(signature);

        try {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

        // EncryptedAssertion encryptedAssertion = encryptAssertion(assertion);

        // response.getEncryptedAssertions().add(encryptedAssertion);
        response.getAssertions().add(assertion);
        return response;
    }

    public Response buildResponseNoIssuer() {

        Response response = buildSAMLObject(Response.class);
        // SP identifies the recipient of the response.
        response.setDestination(SP_ASSERTION_CONSUMER_SERVICE);
        response.setIssueInstant(DateTime.now());
        // Where ID is a string uniquely identifying the response.
        response.setID(generateSecureRandomId());
        Issuer issuer2 = buildSAMLObject(Issuer.class);
        issuer2.setValue(IDP_ENTITY_ID);

        // IdP identifies the identity provider authorizing the response.
        // response.setIssuer(issuer2);

        Status status2 = buildSAMLObject(Status.class);
        StatusCode statusCode2 = buildSAMLObject(StatusCode.class);
        statusCode2.setValue(StatusCode.SUCCESS);
        status2.setStatusCode(statusCode2);

        response.setStatus(status2);

        Assertion assertion = buildAssertion();


        // Sign the assertion with private key of idp
        Signature signature = buildSAMLObject(Signature.class);
        signature.setSigningCredential(getCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        assertion.setSignature(signature);

        try {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

        // EncryptedAssertion encryptedAssertion = encryptAssertion(assertion);

        // response.getEncryptedAssertions().add(encryptedAssertion);
        response.getAssertions().add(assertion);
        return response;
    }

    public Response buildStatusOnlyResponse() {

        Response response = buildSAMLObject(Response.class);
        // SP identifies the recipient of the response.
        response.setDestination(SP_ASSERTION_CONSUMER_SERVICE);
        response.setIssueInstant(DateTime.now());
        // Where ID is a string uniquely identifying the response.
        response.setID(generateSecureRandomId());
        Issuer issuer2 = buildSAMLObject(Issuer.class);
        issuer2.setValue(IDP_ENTITY_ID);

        // IdP identifies the identity provider authorizing the response.
        response.setIssuer(issuer2);

        Status status2 = buildSAMLObject(Status.class);
        StatusCode statusCode2 = buildSAMLObject(StatusCode.class);
        statusCode2.setValue(StatusCode.SUCCESS);
        status2.setStatusCode(statusCode2);

        response.setStatus(status2);

        Assertion assertion = buildAssertion();


        // Sign the assertion with private key of idp
        Signature signature = buildSAMLObject(Signature.class);
        signature.setSigningCredential(getCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        assertion.setSignature(signature);

        try {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

        // EncryptedAssertion encryptedAssertion = encryptAssertion(assertion);

        // response.getEncryptedAssertions().add(encryptedAssertion);
        // response.getAssertions().add(assertion);
        return response;
    }

    private Assertion buildAssertion() {

        Assertion assertion = buildSAMLObject(Assertion.class);

        Issuer issuer = buildSAMLObject(Issuer.class);
        issuer.setValue(IDP_ENTITY_ID);
        assertion.setIssuer(issuer);
        assertion.setIssueInstant(DateTime.now());

        assertion.setID(generateSecureRandomId());

        Subject subject = buildSAMLObject(Subject.class);
        assertion.setSubject(subject);

        NameID nameID = buildSAMLObject(NameID.class);
        nameID.setFormat(NameIDType.TRANSIENT);
        nameID.setValue("Some NameID value");
        nameID.setSPNameQualifier("SP name qualifier");
        nameID.setNameQualifier("Name qualifier");

        subject.setNameID(nameID);

        return assertion;
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





















