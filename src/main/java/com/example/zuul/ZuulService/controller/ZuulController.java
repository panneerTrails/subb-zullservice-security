package com.example.zuul.ZuulService.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ZuulController {



    @GetMapping(value="/")
    public String sayHellow( ) {

        return "Hi from ZUUL CONTROLLER " ;
    }


}
