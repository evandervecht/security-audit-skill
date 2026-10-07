// SA-SPRING-02: Safe search without SpEL — uses JPA Specification
import org.springframework.data.jpa.domain.Specification;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class SearchController {

    private final ProductRepository productRepository;

    public SearchController(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }

    @GetMapping("/search")
    public List<Product> search(@RequestParam String name) {
        Specification<Product> spec = (root, cq, cb) ->
            cb.like(cb.lower(root.get("name")), "%" + name.toLowerCase() + "%");
        return productRepository.findAll(spec);
    }
}
