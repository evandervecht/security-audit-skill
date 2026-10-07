// SA-SPRING-03: Actuator restricted to health and info only
import org.springframework.boot.actuate.autoconfigure.endpoint.web.WebEndpointProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
public class ActuatorConfig {

    @Bean
    public WebEndpointProperties webEndpointProperties() {
        WebEndpointProperties props = new WebEndpointProperties();
        props.getExposure().setInclude(Set.of("health", "info"));
        return props;
    }
}
