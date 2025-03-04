package com.fellow.jwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/secured")
    @PreAuthorize("hasAuthority('WRITE')")
    public String test(){
        return "testing started";
    }
}
