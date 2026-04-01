// SA-SPRING-03: Actuator wildcard exposure in configuration
// Simulated as Java-based properties configuration
import org.springframework.boot.actuate.autoconfigure.endpoint.web.WebEndpointProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
public class ActuatorConfig {

    // This is equivalent to: management.endpoints.web.exposure.include=*
    @Bean
    public WebEndpointProperties webEndpointProperties() {
        WebEndpointProperties props = new WebEndpointProperties();
        // exposure.include = * exposes env, heapdump, configprops, etc.
        props.getExposure().setInclude(Set.of("*"));
        return props;
    }
}
