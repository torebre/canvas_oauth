package com.kjipo.client;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Map;

@Controller
public class ReponseController {


    @GetMapping("/response")
    public String login(@RequestParam Map<String, String> queryParameters, Model model) {
        if(queryParameters.containsKey("code")) {
            model.addAttribute("code", queryParameters.get("code"));
        }
        if(queryParameters.containsKey("error")) {
            model.addAttribute("error", queryParameters.get("error"));
        }
        if(queryParameters.containsKey("error_description")) {
           model.addAttribute("error_description", queryParameters.get("error_description"));
        }


        return "response";
    }

}
