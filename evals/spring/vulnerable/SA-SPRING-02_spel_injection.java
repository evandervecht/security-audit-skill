// SA-SPRING-02: SpEL injection via user-controlled expression
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {

    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/search")
    public Object search(@RequestParam String query) {
        Expression exp = parser.parseExpression(query);
        return exp.getValue();
    }
}
