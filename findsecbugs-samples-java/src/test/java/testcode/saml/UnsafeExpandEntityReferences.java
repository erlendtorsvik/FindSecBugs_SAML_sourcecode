package testcode.saml;


import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.context.annotation.Bean;


public class UnsafeExpandEntityReferences {

    @Bean
    public ParserPool parserPoolOne() {
        BasicParserPool pool = new BasicParserPool();
        pool.setExpandEntityReferences(true);
        return pool;
    }

    @Bean
    public ParserPool parserPoolTwo() {
        StaticBasicParserPool pool = new StaticBasicParserPool();
        pool.setExpandEntityReferences(true);
        return pool;
    }

}
