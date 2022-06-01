package testcode.saml;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.io.IOException;


public class UnsafeGetElementByTagName {

    public static String getEmail(Document doc){
        // Usage of unsafe function getElementsByTagName
        String a = doc.getElementsByTagName("email").item(0).getTextContent();
        return a;
    }


    public static void main(String[] args) throws ParserConfigurationException, IOException, SAXException {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        Document doc = db.parse(UnsafeGetElementByTagName.class.getResourceAsStream("/testcode/xml/simple.xml"));
        String b = getEmail(doc);
        System.out.println(b);
    }
}

