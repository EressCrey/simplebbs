// package com.easybbs.config;
//
// import org.springframework.context.annotation.Configuration;
// import org.springframework.web.servlet.config.annotation.CorsRegistry;
// import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//
// /**
//  *跨域配置
//  */
// @Configuration
// public class CorConfig implements WebMvcConfigurer {
//     @Override
//     public void addCorsMappings(CorsRegistry registry) {
//         registry.addMapping("/**")
//                 .allowedOrigins("*")
//                 .allowCredentials(true)
//                 .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
//                 .maxAge(3600);
//     }
// }