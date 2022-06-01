package testcode.saml;


import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.springframework.context.annotation.Bean;


public class SafeExpandEntityReference {

    boolean expandEntity = false;

    @Bean
    public ParserPool parserPoolOne() {
        BasicParserPool pool = new BasicParserPool();
        pool.setExpandEntityReferences(false);
        return pool;
    }

    @Bean
    public ParserPool parserPoolTwo() {
        BasicParserPool pool = new BasicParserPool();
        pool.setExpandEntityReferences(expandEntity);
        return pool;
    }

}
