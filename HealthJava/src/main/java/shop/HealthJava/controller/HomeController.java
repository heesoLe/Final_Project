package shop.HealthJava.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/product")
public class HomeController {

	@GetMapping("/index")
    public String index() {
        return "/product/mainProduct"; // "product/index"는 반환할 뷰의 이름입니다. 스프링 부트는 이를 통해 "product/index.html"을 찾을 것입니다.
    }
}
